//! Append-only JSONL audit log of every command request.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::Serialize;

use crate::exec::Outcome;

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allowed,
    Denied,
    Error,
}

#[derive(Debug, Default, Serialize)]
pub struct Event<'a> {
    pub tool: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<Decision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<Outcome>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u128>,
}

/// Who issued a request: from `--client-id` + `SSH_CONNECTION` (stdio over SSH),
/// or from the matched key id + peer address (HTTP).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Caller {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,
}

impl Caller {
    pub fn from_ssh_env(client_id: Option<String>) -> Self {
        Self {
            client_id,
            remote: std::env::var("SSH_CONNECTION").ok(),
        }
    }
}

#[derive(Serialize)]
struct Record<'a> {
    ts_ms: u128,
    pid: u32,
    #[serde(flatten)]
    caller: &'a Caller,
    #[serde(flatten)]
    event: &'a Event<'a>,
}

pub struct Audit {
    file: Option<Mutex<File>>,
}

impl Audit {
    pub fn new(path: Option<&Path>) -> std::io::Result<Self> {
        let file = match path {
            Some(p) => Some(Mutex::new(
                OpenOptions::new().create(true).append(true).open(p)?,
            )),
            None => None,
        };
        Ok(Self { file })
    }

    pub fn log(&self, caller: &Caller, event: &Event<'_>) {
        let record = Record {
            ts_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            pid: std::process::id(),
            caller,
            event,
        };
        let line = match serde_json::to_string(&record) {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("audit serialization failed: {e}");
                return;
            }
        };
        match &self.file {
            Some(f) => {
                let mut f = f.lock().unwrap();
                if let Err(e) = writeln!(f, "{line}") {
                    tracing::error!("audit write failed: {e}");
                }
            }
            None => tracing::info!(target: "audit", "{line}"),
        }
    }
}
