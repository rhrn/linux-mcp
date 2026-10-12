//! Runs validated pipelines: no shell, own process group, bounded time and output.

use std::path::Path;
use std::process::{ExitStatus, Stdio};
use std::time::{Duration, Instant};

use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};
use tokio::sync::mpsc::UnboundedSender;
use tokio_util::sync::CancellationToken;

use crate::policy::Stage;

const TERM_GRACE: Duration = Duration::from_secs(2);
/// After the last stage exits, earlier stages get this long before being killed.
const PIPE_GRACE: Duration = Duration::from_millis(500);

pub struct ExecSpec<'a> {
    pub stages: &'a [Stage],
    pub cwd: &'a Path,
    pub env: &'a [(String, String)],
    pub timeout: Duration,
    /// Collect stdout up to this many bytes; exceeding it stops the pipeline.
    /// `None` = don't collect (output only goes to the chunk channel).
    pub stdout_cap: Option<usize>,
    pub stderr_cap: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Completed,
    TimedOut,
    Cancelled,
    OutputLimit,
}

#[derive(Debug)]
pub struct ExecResult {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub stderr_truncated: bool,
    /// Exit code of the last stage (like `sh` without `pipefail`).
    pub exit_code: Option<i32>,
    pub signal: Option<i32>,
    pub outcome: Outcome,
    pub duration: Duration,
}

/// Spawn the pipeline and wait for it. Chunks of the last stage's stdout are
/// sent to `chunks` as they arrive.
pub async fn run(
    spec: ExecSpec<'_>,
    ct: CancellationToken,
    chunks: Option<UnboundedSender<Vec<u8>>>,
) -> std::io::Result<ExecResult> {
    assert!(!spec.stages.is_empty());
    let started = Instant::now();
    let deadline = tokio::time::Instant::now() + spec.timeout;

    let mut children: Vec<Child> = Vec::with_capacity(spec.stages.len());
    let mut stderr_tasks = Vec::with_capacity(spec.stages.len());
    let mut pgid: Option<i32> = None;
    let mut prev_stdout: Option<Stdio> = None;
    let last = spec.stages.len() - 1;

    for (i, stage) in spec.stages.iter().enumerate() {
        let mut cmd = Command::new(&stage.binary);
        cmd.args(&stage.args)
            .current_dir(spec.cwd)
            .env_clear()
            .envs(spec.env.iter().map(|(k, v)| (k, v)))
            .stdin(prev_stdout.take().unwrap_or_else(Stdio::null))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(pgid.unwrap_or(0));
        let mut child = match cmd.spawn() {
            Ok(c) => c,
            Err(e) => {
                if let Some(g) = pgid {
                    terminate(g, &mut children).await;
                }
                return Err(std::io::Error::new(
                    e.kind(),
                    format!("failed to start {}: {e}", stage.binary.display()),
                ));
            }
        };
        if pgid.is_none() {
            pgid = child.id().map(|p| p as i32);
        }
        let stderr = child.stderr.take().expect("piped stderr");
        stderr_tasks.push(tokio::spawn(read_capped(stderr, spec.stderr_cap)));
        if i < last {
            let out = child.stdout.take().expect("piped stdout");
            prev_stdout = Some(Stdio::from(out.into_owned_fd()?));
        }
        children.push(child);
    }
    let pgid = pgid.expect("at least one child spawned");

    let mut stdout = children[last].stdout.take().expect("piped stdout");
    let mut collected = Vec::new();
    let mut outcome = Outcome::Completed;
    let mut buf = vec![0u8; 16 * 1024];

    // Phase 1: pump stdout until EOF, timeout, cancel or output limit.
    loop {
        tokio::select! {
            biased;
            _ = ct.cancelled() => { outcome = Outcome::Cancelled; break; }
            _ = tokio::time::sleep_until(deadline) => { outcome = Outcome::TimedOut; break; }
            r = stdout.read(&mut buf) => {
                let n = match r { Ok(0) | Err(_) => break, Ok(n) => n };
                if let Some(tx) = &chunks {
                    let _ = tx.send(buf[..n].to_vec());
                }
                if let Some(cap) = spec.stdout_cap {
                    let room = cap.saturating_sub(collected.len());
                    collected.extend_from_slice(&buf[..n.min(room)]);
                    if n > room {
                        outcome = Outcome::OutputLimit;
                        break;
                    }
                }
            }
        }
    }
    drop(stdout);

    // Phase 2: reap. On normal EOF wait for the last stage, then give the rest a short grace.
    if outcome == Outcome::Completed {
        let waited = tokio::select! {
            biased;
            _ = ct.cancelled() => Some(Outcome::Cancelled),
            _ = tokio::time::sleep_until(deadline) => Some(Outcome::TimedOut),
            _ = children[last].wait() => None,
        };
        if let Some(o) = waited {
            outcome = o;
        } else {
            let grace = tokio::time::Instant::now() + PIPE_GRACE;
            let _ = tokio::time::timeout_at(grace.min(deadline), wait_all(&mut children)).await;
        }
    }
    terminate(pgid, &mut children).await;

    let status: Option<ExitStatus> = children[last].try_wait().ok().flatten();
    let (exit_code, signal) = match status {
        Some(s) => (s.code(), exit_signal(&s)),
        None => (None, None),
    };

    let mut stderr = Vec::new();
    let mut stderr_truncated = false;
    for (i, task) in stderr_tasks.into_iter().enumerate() {
        let (bytes, trunc) = match tokio::time::timeout(Duration::from_secs(1), task).await {
            Ok(Ok(r)) => r,
            _ => (Vec::new(), false),
        };
        stderr_truncated |= trunc;
        if bytes.is_empty() {
            continue;
        }
        if spec.stages.len() > 1 {
            stderr.extend_from_slice(format!("[{}] ", spec.stages[i].name).as_bytes());
        }
        stderr.extend_from_slice(&bytes);
        if !bytes.ends_with(b"\n") {
            stderr.push(b'\n');
        }
    }

    Ok(ExecResult {
        stdout: collected,
        stderr,
        stderr_truncated,
        exit_code,
        signal,
        outcome,
        duration: started.elapsed(),
    })
}

async fn wait_all(children: &mut [Child]) {
    for c in children.iter_mut() {
        let _ = c.wait().await;
    }
}

fn all_exited(children: &mut [Child]) -> bool {
    children
        .iter_mut()
        .all(|c| !matches!(c.try_wait(), Ok(None)))
}

/// SIGTERM the process group, then SIGKILL after a grace period.
async fn terminate(pgid: i32, children: &mut [Child]) {
    if all_exited(children) {
        return;
    }
    signal_group(pgid, libc::SIGTERM);
    if tokio::time::timeout(TERM_GRACE, wait_all(children))
        .await
        .is_err()
    {
        signal_group(pgid, libc::SIGKILL);
        wait_all(children).await;
    }
}

fn signal_group(pgid: i32, sig: i32) {
    // SAFETY: killpg has no memory-safety preconditions; pgid is a group we created
    // and whose members we have not yet reaped.
    unsafe {
        libc::killpg(pgid, sig);
    }
}

#[cfg(unix)]
fn exit_signal(s: &ExitStatus) -> Option<i32> {
    use std::os::unix::process::ExitStatusExt;
    s.signal()
}

async fn read_capped<R: AsyncRead + Unpin>(mut r: R, cap: usize) -> (Vec<u8>, bool) {
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];
    let mut truncated = false;
    loop {
        match r.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let room = cap.saturating_sub(out.len());
                out.extend_from_slice(&buf[..n.min(room)]);
                truncated |= n > room; // keep draining so the writer never blocks
            }
        }
    }
    (out, truncated)
}

/// Lossy UTF-8 decode, strip ANSI escape sequences and stray control characters.
pub fn clean_text(bytes: &[u8]) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out = String::with_capacity(s.len());
    let mut it = s.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\x1b' => match it.next() {
                Some('[') => {
                    // CSI: parameters/intermediates then a final byte in @..~
                    for c in it.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: until BEL or ESC \
                    while let Some(c) = it.next() {
                        if c == '\x07' {
                            break;
                        }
                        if c == '\x1b' && it.peek() == Some(&'\\') {
                            it.next();
                            break;
                        }
                    }
                }
                _ => {}
            },
            '\n' | '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn stage(bin: &str, args: &[&str]) -> Stage {
        Stage {
            name: Path::new(bin).file_name().unwrap().to_string_lossy().into(),
            binary: PathBuf::from(bin),
            args: args.iter().map(|s| s.to_string()).collect(),
        }
    }

    fn env() -> Vec<(String, String)> {
        vec![("PATH".into(), "/usr/bin:/bin".into())]
    }

    async fn exec(stages: &[Stage], timeout_ms: u64, cap: usize) -> ExecResult {
        let env = env();
        let dir = std::env::temp_dir();
        run(
            ExecSpec {
                stages,
                cwd: &dir,
                env: &env,
                timeout: Duration::from_millis(timeout_ms),
                stdout_cap: Some(cap),
                stderr_cap: 4096,
            },
            CancellationToken::new(),
            None,
        )
        .await
        .unwrap()
    }

    #[tokio::test]
    async fn simple_and_pipeline() {
        let r = exec(&[stage("/bin/echo", &["hello world"])], 5000, 1 << 20).await;
        assert_eq!(r.stdout, b"hello world\n");
        assert_eq!(r.exit_code, Some(0));
        assert_eq!(r.outcome, Outcome::Completed);

        let r = exec(
            &[
                stage("/usr/bin/printf", &["a\\nb\\npostgres\\n"]),
                stage("/usr/bin/grep", &["postgres"]),
            ],
            5000,
            1 << 20,
        )
        .await;
        assert_eq!(r.stdout, b"postgres\n");
        assert_eq!(r.exit_code, Some(0));
    }

    #[tokio::test]
    async fn exit_code_of_last_stage() {
        let r = exec(
            &[
                stage("/bin/echo", &["x"]),
                stage("/usr/bin/grep", &["nomatch"]),
            ],
            5000,
            1 << 20,
        )
        .await;
        assert_eq!(r.exit_code, Some(1));
    }

    #[tokio::test]
    async fn environment_is_cleared() {
        let r = exec(&[stage("/usr/bin/env", &[])], 5000, 1 << 20).await;
        assert_eq!(
            String::from_utf8_lossy(&r.stdout).trim(),
            "PATH=/usr/bin:/bin"
        );
    }

    #[tokio::test]
    async fn timeout_kills_group() {
        let started = Instant::now();
        let r = exec(
            &[stage("/bin/sleep", &["30"]), stage("/bin/cat", &[])],
            300,
            1 << 20,
        )
        .await;
        assert_eq!(r.outcome, Outcome::TimedOut);
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[tokio::test]
    async fn output_cap_stops_infinite_output() {
        let r = exec(&[stage("/usr/bin/yes", &[])], 10_000, 1000).await;
        assert_eq!(r.outcome, Outcome::OutputLimit);
        assert_eq!(r.stdout.len(), 1000);
    }

    #[tokio::test]
    async fn cancel_stops() {
        let ct = CancellationToken::new();
        let c2 = ct.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            c2.cancel();
        });
        let env = env();
        let dir = std::env::temp_dir();
        let stages = [stage("/bin/sleep", &["30"])];
        let r = run(
            ExecSpec {
                stages: &stages,
                cwd: &dir,
                env: &env,
                timeout: Duration::from_secs(30),
                stdout_cap: Some(100),
                stderr_cap: 100,
            },
            ct,
            None,
        )
        .await
        .unwrap();
        assert_eq!(r.outcome, Outcome::Cancelled);
    }

    #[tokio::test]
    async fn streams_chunks() {
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
        let env = env();
        let dir = std::env::temp_dir();
        let stages = [stage("/bin/echo", &["chunk"])];
        let r = run(
            ExecSpec {
                stages: &stages,
                cwd: &dir,
                env: &env,
                timeout: Duration::from_secs(5),
                stdout_cap: None,
                stderr_cap: 100,
            },
            CancellationToken::new(),
            Some(tx),
        )
        .await
        .unwrap();
        assert!(r.stdout.is_empty());
        let mut got = Vec::new();
        while let Some(c) = rx.recv().await {
            got.extend(c);
        }
        assert_eq!(got, b"chunk\n");
    }

    #[tokio::test]
    async fn stderr_is_labeled_in_pipelines() {
        let r = exec(
            &[
                stage("/bin/ls", &["/definitely-missing"]),
                stage("/bin/cat", &[]),
            ],
            5000,
            1 << 20,
        )
        .await;
        let err = String::from_utf8_lossy(&r.stderr);
        assert!(err.starts_with("[ls] "), "{err}");
    }

    #[test]
    fn strips_ansi() {
        assert_eq!(clean_text(b"\x1b[31mred\x1b[0m ok\r\n"), "red ok\n");
        assert_eq!(clean_text(b"\x1b]0;title\x07x"), "x");
        assert_eq!(clean_text(b"bad \xff byte"), "bad \u{fffd} byte");
    }
}
