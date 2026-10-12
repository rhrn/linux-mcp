//! Background stream sessions (`docker logs -f`, `docker events`, ...) read incrementally.

use std::collections::{HashMap, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tokio::sync::{Notify, OwnedSemaphorePermit};
use tokio_util::sync::CancellationToken;

use crate::exec::{self, ExecResult, ExecSpec, Outcome};
use crate::policy::Stage;

pub struct StreamConfig {
    pub stages: Vec<Stage>,
    pub cwd: PathBuf,
    pub env: Vec<(String, String)>,
    pub duration: Duration,
    /// Unread output beyond this is dropped (oldest first).
    pub buffer_cap: usize,
    pub stderr_cap: usize,
}

#[derive(Debug, Clone)]
pub struct Finished {
    pub outcome: Option<Outcome>,
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub stderr: String,
    pub error: Option<String>,
    pub duration: Duration,
}

pub struct ReadResult {
    pub data: String,
    pub dropped_bytes: u64,
    pub finished: Option<Finished>,
    /// Bytes still buffered after this read.
    pub pending_bytes: usize,
}

pub struct StreamInfo {
    pub id: String,
    pub command: String,
    pub running: bool,
    pub age: Duration,
    pub pending_bytes: usize,
}

struct Buffer {
    data: VecDeque<u8>,
    dropped: u64,
    finished: Option<Finished>,
    last_read: Instant,
}

struct Session {
    command: String,
    started: Instant,
    buf: Mutex<Buffer>,
    notify: Notify,
    ct: CancellationToken,
}

#[derive(Debug, thiserror::Error)]
pub enum StreamError {
    #[error("unknown stream id '{0}' (it may have finished and been collected; see stream_list)")]
    Unknown(String),
    #[error("too many open streams (max {0}); stop one first")]
    TooMany(usize),
}

pub struct StreamManager {
    sessions: Mutex<HashMap<String, Arc<Session>>>,
    next_id: AtomicU64,
    max_streams: usize,
    idle_ttl: Duration,
}

impl StreamManager {
    pub fn new(max_streams: usize, idle_ttl: Duration) -> Arc<Self> {
        let mgr = Arc::new(Self {
            sessions: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
            max_streams,
            idle_ttl,
        });
        let weak = Arc::downgrade(&mgr);
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(Duration::from_secs(5));
            loop {
                tick.tick().await;
                let Some(mgr) = weak.upgrade() else { break };
                mgr.reap_idle();
            }
        });
        mgr
    }

    pub fn start(
        &self,
        command: String,
        cfg: StreamConfig,
        permit: OwnedSemaphorePermit,
    ) -> Result<String, StreamError> {
        let mut sessions = self.sessions.lock().unwrap();
        if sessions.len() >= self.max_streams {
            return Err(StreamError::TooMany(self.max_streams));
        }
        let id = format!("s{}", self.next_id.fetch_add(1, Ordering::Relaxed));
        let session = Arc::new(Session {
            command,
            started: Instant::now(),
            buf: Mutex::new(Buffer {
                data: VecDeque::new(),
                dropped: 0,
                finished: None,
                last_read: Instant::now(),
            }),
            notify: Notify::new(),
            ct: CancellationToken::new(),
        });
        sessions.insert(id.clone(), session.clone());
        tokio::spawn(run_session(session, cfg, permit));
        Ok(id)
    }

    /// Read buffered output, waiting up to `wait` for data if none is buffered.
    pub async fn read(
        &self,
        id: &str,
        max_bytes: usize,
        wait: Duration,
    ) -> Result<ReadResult, StreamError> {
        let session = self.get(id)?;
        let deadline = tokio::time::Instant::now() + wait;
        loop {
            let notified = session.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            {
                let mut b = session.buf.lock().unwrap();
                b.last_read = Instant::now();
                let ready = !b.data.is_empty() || b.finished.is_some();
                if ready || tokio::time::Instant::now() >= deadline {
                    let result = take(&mut b, max_bytes);
                    drop(b);
                    if result.finished.is_some() && result.pending_bytes == 0 {
                        self.sessions.lock().unwrap().remove(id);
                    }
                    return Ok(result);
                }
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
    }

    /// Stop a stream and return whatever is still buffered.
    pub async fn stop(&self, id: &str, max_bytes: usize) -> Result<ReadResult, StreamError> {
        let session = self.get(id)?;
        session.ct.cancel();
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            let notified = session.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if session.buf.lock().unwrap().finished.is_some()
                || tokio::time::Instant::now() >= deadline
            {
                break;
            }
            let _ = tokio::time::timeout_at(deadline, notified).await;
        }
        self.sessions.lock().unwrap().remove(id);
        let mut b = session.buf.lock().unwrap();
        Ok(take(&mut b, max_bytes))
    }

    pub fn list(&self) -> Vec<StreamInfo> {
        let sessions = self.sessions.lock().unwrap();
        let mut out: Vec<_> = sessions
            .iter()
            .map(|(id, s)| {
                let b = s.buf.lock().unwrap();
                StreamInfo {
                    id: id.clone(),
                    command: s.command.clone(),
                    running: b.finished.is_none(),
                    age: s.started.elapsed(),
                    pending_bytes: b.data.len(),
                }
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }

    fn get(&self, id: &str) -> Result<Arc<Session>, StreamError> {
        self.sessions
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .ok_or_else(|| StreamError::Unknown(id.into()))
    }

    fn reap_idle(&self) {
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|id, s| {
            let idle = s.buf.lock().unwrap().last_read.elapsed() > self.idle_ttl;
            if idle {
                tracing::info!(stream = %id, "stream idle, stopping");
                s.ct.cancel();
            }
            !idle
        });
    }
}

/// Streams belong to one MCP session; when it goes away, so do its streams.
impl Drop for StreamManager {
    fn drop(&mut self) {
        let sessions = self.sessions.get_mut().unwrap_or_else(|e| e.into_inner());
        for s in sessions.values() {
            s.ct.cancel();
        }
    }
}

async fn run_session(session: Arc<Session>, cfg: StreamConfig, permit: OwnedSemaphorePermit) {
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let cap = cfg.buffer_cap;
    let s2 = session.clone();
    let pump = tokio::spawn(async move {
        while let Some(chunk) = rx.recv().await {
            let mut b = s2.buf.lock().unwrap();
            b.data.extend(chunk);
            let over = b.data.len().saturating_sub(cap);
            if over > 0 {
                b.data.drain(..over);
                b.dropped += over as u64;
            }
            drop(b);
            s2.notify.notify_waiters();
        }
    });

    let result = exec::run(
        ExecSpec {
            stages: &cfg.stages,
            cwd: &cfg.cwd,
            env: &cfg.env,
            timeout: cfg.duration,
            stdout_cap: None,
            stderr_cap: cfg.stderr_cap,
        },
        session.ct.clone(),
        Some(tx),
    )
    .await;
    let _ = pump.await;
    drop(permit);

    let finished = match result {
        Ok(ExecResult {
            stderr,
            exit_code,
            signal,
            outcome,
            duration,
            ..
        }) => Finished {
            outcome: Some(outcome),
            exit_code,
            signal,
            stderr: exec::clean_text(&stderr),
            error: None,
            duration,
        },
        Err(e) => Finished {
            outcome: None,
            exit_code: None,
            signal: None,
            stderr: String::new(),
            error: Some(e.to_string()),
            duration: session.started.elapsed(),
        },
    };
    tracing::debug!(command = %session.command, ?finished.outcome, "stream finished");
    session.buf.lock().unwrap().finished = Some(finished);
    session.notify.notify_waiters();
}

/// Take up to `max_bytes` from the buffer without splitting a UTF-8 character.
fn take(b: &mut Buffer, max_bytes: usize) -> ReadResult {
    let n = b.data.len().min(max_bytes);
    let mut bytes: Vec<u8> = b.data.range(..n).copied().collect();
    if n < b.data.len()
        && let Err(e) = std::str::from_utf8(&bytes)
        && e.error_len().is_none()
        && e.valid_up_to() > 0
    {
        bytes.truncate(e.valid_up_to());
    }
    b.data.drain(..bytes.len());
    let dropped = std::mem::take(&mut b.dropped);
    ReadResult {
        data: exec::clean_text(&bytes),
        dropped_bytes: dropped,
        // Only report completion once everything has been read.
        finished: if b.data.is_empty() {
            b.finished.clone()
        } else {
            None
        },
        pending_bytes: b.data.len(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::sync::Semaphore;

    fn cfg(bin: &str, args: &[&str], secs: u64, cap: usize) -> StreamConfig {
        StreamConfig {
            stages: vec![Stage {
                name: "t".into(),
                binary: bin.into(),
                args: args.iter().map(|s| s.to_string()).collect(),
            }],
            cwd: std::env::temp_dir(),
            env: vec![("PATH".into(), "/usr/bin:/bin".into())],
            duration: Duration::from_secs(secs),
            buffer_cap: cap,
            stderr_cap: 1024,
        }
    }

    fn permit() -> OwnedSemaphorePermit {
        Arc::new(Semaphore::new(1)).try_acquire_owned().unwrap()
    }

    #[tokio::test]
    async fn read_until_finished() {
        let mgr = StreamManager::new(2, Duration::from_secs(60));
        let id = mgr
            .start("echo".into(), cfg("/bin/echo", &["hi"], 5, 1024), permit())
            .unwrap();
        let mut out = String::new();
        loop {
            let r = mgr.read(&id, 1024, Duration::from_secs(2)).await.unwrap();
            out.push_str(&r.data);
            if let Some(f) = r.finished {
                assert_eq!(f.exit_code, Some(0));
                break;
            }
        }
        assert_eq!(out, "hi\n");
        // collected after completion
        assert!(mgr.read(&id, 1, Duration::ZERO).await.is_err());
    }

    #[tokio::test]
    async fn ring_buffer_drops_oldest_and_stop_works() {
        let mgr = StreamManager::new(2, Duration::from_secs(60));
        let id = mgr
            .start("yes".into(), cfg("/usr/bin/yes", &[], 30, 100), permit())
            .unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        let r = mgr.read(&id, 1000, Duration::ZERO).await.unwrap();
        assert!(r.data.len() <= 100);
        assert!(r.dropped_bytes > 0);
        let r = mgr.stop(&id, 1000).await.unwrap();
        assert!(
            r.finished
                .is_some_and(|f| f.outcome == Some(Outcome::Cancelled))
        );
        assert!(mgr.list().is_empty());
    }

    #[tokio::test]
    async fn max_streams_enforced() {
        let mgr = StreamManager::new(1, Duration::from_secs(60));
        let a = mgr
            .start("sleep".into(), cfg("/bin/sleep", &["30"], 30, 10), permit())
            .unwrap();
        assert!(matches!(
            mgr.start("sleep".into(), cfg("/bin/sleep", &["30"], 30, 10), permit()),
            Err(StreamError::TooMany(1))
        ));
        mgr.stop(&a, 10).await.unwrap();
    }

    #[tokio::test]
    async fn drop_cancels_streams() {
        let mgr = StreamManager::new(1, Duration::from_secs(60));
        mgr.start("sleep".into(), cfg("/bin/sleep", &["30"], 30, 10), permit())
            .unwrap();
        let session = mgr
            .sessions
            .lock()
            .unwrap()
            .values()
            .next()
            .unwrap()
            .clone();
        drop(mgr);
        assert!(session.ct.is_cancelled());
    }
}
