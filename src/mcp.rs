//! MCP tool surface.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use rmcp::handler::server::router::tool::ToolRouter;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{
    CallToolResult, ContentBlock, Implementation, ProgressNotificationParam, ServerCapabilities,
    ServerConfig,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler, tool, tool_handler, tool_router};
use schemars::JsonSchema;
use serde::Deserialize;
use tokio::sync::Semaphore;

use crate::audit::{Audit, Caller, Decision, Event};
use crate::config::ServerSettings;
use crate::exec::{self, ExecSpec, Outcome};
use crate::parser;
use crate::policy::{Policy, Stage};
use crate::stream::{Finished, ReadResult, StreamConfig, StreamManager};

const STDERR_CAP: usize = 64 * 1024;
const DEFAULT_READ_BYTES: usize = 64 * 1024;
const MAX_WAIT_MS: u64 = 30_000;

pub struct State {
    pub policy: Policy,
    pub settings: ServerSettings,
    pub workdir: PathBuf,
    pub env: Vec<(String, String)>,
    pub sem: Arc<Semaphore>,
    pub audit: Audit,
}

impl State {
    pub fn new(policy: Policy, settings: ServerSettings, audit: Audit) -> anyhow::Result<Self> {
        let workdir = settings
            .workdir
            .canonicalize()
            .map_err(|e| anyhow::anyhow!("server.workdir {}: {e}", settings.workdir.display()))?;
        policy
            .check_cwd(&workdir, &workdir)
            .map_err(|_| anyhow::anyhow!("server.workdir must be inside server.allowed_paths"))?;
        let mut env = vec![
            ("PATH".to_owned(), settings.path_env.clone()),
            ("LANG".to_owned(), "C.UTF-8".to_owned()),
        ];
        if let Ok(home) = std::env::var("HOME") {
            env.push(("HOME".to_owned(), home));
        }
        env.extend(settings.env.iter().map(|(k, v)| (k.clone(), v.clone())));
        Ok(Self {
            sem: Arc::new(Semaphore::new(settings.max_concurrent)),
            policy,
            workdir,
            env,
            settings,
            audit,
        })
    }

    /// Parse + validate. Returns (normalized command, stages, cwd) or a denial reason.
    pub fn prepare(
        &self,
        command: &str,
        cwd: Option<&str>,
    ) -> Result<(String, Vec<Stage>, PathBuf), String> {
        let pipeline = parser::parse(command).map_err(|e| format!("parse error: {e}"))?;
        let cwd = match cwd {
            Some(c) => self
                .policy
                .check_cwd(Path::new(c), &self.workdir)
                .map_err(|e| e.to_string())?,
            None => self.workdir.clone(),
        };
        let stages = self
            .policy
            .check(&pipeline, &cwd)
            .map_err(|e| e.to_string())?;
        Ok((parser::render(&pipeline), stages, cwd))
    }

    fn timeout(&self, requested: Option<u64>) -> Duration {
        let s = requested
            .unwrap_or(self.settings.default_timeout_s)
            .clamp(1, self.settings.max_timeout_s);
        Duration::from_secs(s)
    }
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct RunArgs {
    /// Command line, e.g. `ls -la` or `docker ps | grep postgres`. Only allowlisted
    /// commands joined with `|`; no `;`, `&&`, redirection, globs or `$VAR`.
    pub command: String,
    /// Seconds before the pipeline is killed. Follow-mode commands (e.g. `docker logs -f`)
    /// run until this expires and return what they collected.
    #[serde(default)]
    pub timeout_s: Option<u64>,
    /// Working directory (must be inside the allowed paths). Defaults to the server workdir.
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StreamStartArgs {
    /// Command line to run in the background, e.g. `docker logs -f --tail 50 web`.
    pub command: String,
    /// Stop automatically after this many seconds.
    #[serde(default)]
    pub max_duration_s: Option<u64>,
    #[serde(default)]
    pub cwd: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StreamReadArgs {
    pub stream_id: String,
    /// Maximum bytes to return (default 65536).
    #[serde(default)]
    pub max_bytes: Option<usize>,
    /// If nothing is buffered, wait up to this many milliseconds for new output (max 30000).
    #[serde(default)]
    pub wait_ms: Option<u64>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct StreamStopArgs {
    pub stream_id: String,
}

/// One instance per MCP session (one per SSH connection, or per HTTP session).
#[derive(Clone)]
pub struct LinuxMcp {
    state: Arc<State>,
    /// Streams are private to the session that started them.
    streams: Arc<StreamManager>,
    /// Identity used when the transport supplies none (stdio over SSH).
    default_caller: Caller,
    /// HTTP: client id of the key that opened the session; other keys may not use it.
    owner: Arc<OnceLock<Option<String>>>,
    #[allow(dead_code)] // used by the tool_handler macro
    tool_router: ToolRouter<Self>,
}

fn text_result(text: String) -> CallToolResult {
    CallToolResult::success(vec![ContentBlock::text(text)])
}

fn error_result(text: String) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text)])
}

#[tool_router]
impl LinuxMcp {
    pub fn new(state: Arc<State>, default_caller: Caller) -> Self {
        Self {
            streams: StreamManager::new(
                state.settings.max_streams,
                Duration::from_secs(state.settings.stream_idle_ttl_s),
            ),
            state,
            default_caller,
            owner: Arc::new(OnceLock::new()),
            tool_router: Self::tool_router(),
        }
    }

    /// Identify the caller: set by the HTTP auth middleware, else the stdio default.
    /// Also enforces that an HTTP session is only used with the key that created it.
    fn caller(&self, ctx: &RequestContext<RoleServer>) -> Result<Caller, CallToolResult> {
        let caller = ctx
            .extensions
            .get::<axum::http::request::Parts>()
            .and_then(|parts| parts.extensions.get::<Caller>())
            .cloned()
            .unwrap_or_else(|| self.default_caller.clone());
        let owner = self.owner.get_or_init(|| caller.client_id.clone());
        if *owner != caller.client_id {
            tracing::warn!(?caller, ?owner, "session used with a different key");
            return Err(error_result(
                "this MCP session belongs to a different client key".into(),
            ));
        }
        Ok(caller)
    }

    #[tool(
        description = "Run an allowlisted command or pipeline on the server and return its output. \
            Syntax: simple commands joined with '|', with quotes and backslash escapes; \
            no ';', '&&', redirection, globs, '~' or variables. Call list_commands to see what is allowed. \
            For long-running/follow output prefer stream_start."
    )]
    async fn run(
        &self,
        Parameters(args): Parameters<RunArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = match self.caller(&ctx) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        let st = &self.state;
        let (command, stages, cwd) = match st.prepare(&args.command, args.cwd.as_deref()) {
            Ok(v) => v,
            Err(reason) => {
                st.audit.log(
                    &caller,
                    &Event {
                        tool: "run",
                        command: Some(&args.command),
                        decision: Some(Decision::Denied),
                        reason: Some(reason.clone()),
                        ..Default::default()
                    },
                );
                return Ok(error_result(format!("denied: {reason}")));
            }
        };

        let _permit = tokio::select! {
            p = st.sem.clone().acquire_owned() => p.expect("semaphore never closed"),
            _ = ctx.ct.cancelled() => return Ok(error_result("cancelled".into())),
        };

        // Forward output as progress notifications when the client asked for progress.
        let progress = ctx.meta.get_progress_token().map(|token| {
            let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
            let peer = ctx.peer.clone();
            let task = tokio::spawn(async move {
                let mut total = 0usize;
                while let Some(chunk) = rx.recv().await {
                    total += chunk.len();
                    let _ = peer
                        .notify_progress(
                            ProgressNotificationParam::new(token.clone(), total as f64)
                                .with_message(exec::clean_text(&chunk)),
                        )
                        .await;
                }
            });
            (tx, task)
        });
        let (tx, progress_task) = match progress {
            Some((tx, task)) => (Some(tx), Some(task)),
            None => (None, None),
        };

        let result = exec::run(
            ExecSpec {
                stages: &stages,
                cwd: &cwd,
                env: &st.env,
                timeout: st.timeout(args.timeout_s),
                stdout_cap: Some(st.settings.max_output_bytes),
                stderr_cap: STDERR_CAP.min(st.settings.max_output_bytes),
            },
            ctx.ct.clone(),
            tx,
        )
        .await;
        if let Some(t) = progress_task {
            let _ = t.await;
        }

        let r = match result {
            Ok(r) => r,
            Err(e) => {
                st.audit.log(
                    &caller,
                    &Event {
                        tool: "run",
                        command: Some(&command),
                        cwd: Some(cwd.display().to_string()),
                        decision: Some(Decision::Error),
                        reason: Some(e.to_string()),
                        ..Default::default()
                    },
                );
                return Ok(error_result(format!("error: {e}")));
            }
        };
        st.audit.log(
            &caller,
            &Event {
                tool: "run",
                command: Some(&command),
                cwd: Some(cwd.display().to_string()),
                decision: Some(Decision::Allowed),
                outcome: Some(r.outcome),
                exit_code: r.exit_code,
                duration_ms: Some(r.duration.as_millis()),
                ..Default::default()
            },
        );

        let mut out = exec::clean_text(&r.stdout);
        let stderr = exec::clean_text(&r.stderr);
        if !stderr.is_empty() {
            if !out.is_empty() && !out.ends_with('\n') {
                out.push('\n');
            }
            let _ = write!(out, "--- stderr ---\n{stderr}");
            if r.stderr_truncated {
                out.push_str("[stderr truncated]\n");
            }
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        let _ = write!(
            out,
            "[{}]",
            status_line(r.exit_code, r.signal, Some(r.outcome), r.duration)
        );
        Ok(text_result(out))
    }

    #[tool(description = "List the commands, subcommands, flags and paths this server allows.")]
    async fn list_commands(&self) -> String {
        self.state.policy.describe()
    }

    #[tool(
        description = "Start a long-running allowlisted command (e.g. `docker logs -f web`, `docker events`) \
            in the background. Returns a stream_id; read output with stream_read and stop with stream_stop."
    )]
    async fn stream_start(
        &self,
        Parameters(args): Parameters<StreamStartArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = match self.caller(&ctx) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        let st = &self.state;
        let (command, stages, cwd) = match st.prepare(&args.command, args.cwd.as_deref()) {
            Ok(v) => v,
            Err(reason) => {
                st.audit.log(
                    &caller,
                    &Event {
                        tool: "stream_start",
                        command: Some(&args.command),
                        decision: Some(Decision::Denied),
                        reason: Some(reason.clone()),
                        ..Default::default()
                    },
                );
                return Ok(error_result(format!("denied: {reason}")));
            }
        };
        let Ok(permit) = st.sem.clone().try_acquire_owned() else {
            return Ok(error_result(format!(
                "too many commands running (max {}); try again later",
                st.settings.max_concurrent
            )));
        };
        let duration = Duration::from_secs(
            args.max_duration_s
                .unwrap_or(st.settings.max_stream_duration_s)
                .clamp(1, st.settings.max_stream_duration_s),
        );
        let started = self.streams.start(
            command.clone(),
            StreamConfig {
                stages,
                cwd: cwd.clone(),
                env: st.env.clone(),
                duration,
                buffer_cap: st.settings.max_output_bytes,
                stderr_cap: STDERR_CAP.min(st.settings.max_output_bytes),
            },
            permit,
        );
        match started {
            Ok(id) => {
                st.audit.log(
                    &caller,
                    &Event {
                        tool: "stream_start",
                        command: Some(&command),
                        cwd: Some(cwd.display().to_string()),
                        decision: Some(Decision::Allowed),
                        stream_id: Some(&id),
                        ..Default::default()
                    },
                );
                Ok(text_result(format!(
                    "stream_id: {id}\ncommand: {command}\nstops after {}s, or when idle (not read) for {}s",
                    duration.as_secs(),
                    st.settings.stream_idle_ttl_s
                )))
            }
            Err(e) => Ok(error_result(e.to_string())),
        }
    }

    #[tool(description = "Read new output from a stream started with stream_start.")]
    async fn stream_read(
        &self,
        Parameters(args): Parameters<StreamReadArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        if let Err(r) = self.caller(&ctx) {
            return Ok(r);
        }
        let max = args
            .max_bytes
            .unwrap_or(DEFAULT_READ_BYTES)
            .clamp(1, self.state.settings.max_output_bytes);
        let wait = Duration::from_millis(args.wait_ms.unwrap_or(0).min(MAX_WAIT_MS));
        match self.streams.read(&args.stream_id, max, wait).await {
            Ok(r) => Ok(text_result(render_read(r, &args.stream_id))),
            Err(e) => Ok(error_result(e.to_string())),
        }
    }

    #[tool(description = "Stop a stream and return any remaining buffered output.")]
    async fn stream_stop(
        &self,
        Parameters(args): Parameters<StreamStopArgs>,
        ctx: RequestContext<RoleServer>,
    ) -> Result<CallToolResult, ErrorData> {
        let caller = match self.caller(&ctx) {
            Ok(c) => c,
            Err(r) => return Ok(r),
        };
        let st = &self.state;
        match self
            .streams
            .stop(&args.stream_id, st.settings.max_output_bytes)
            .await
        {
            Ok(r) => {
                st.audit.log(
                    &caller,
                    &Event {
                        tool: "stream_stop",
                        stream_id: Some(&args.stream_id),
                        outcome: r.finished.as_ref().and_then(|f| f.outcome),
                        exit_code: r.finished.as_ref().and_then(|f| f.exit_code),
                        duration_ms: r.finished.as_ref().map(|f| f.duration.as_millis()),
                        ..Default::default()
                    },
                );
                Ok(text_result(render_read(r, &args.stream_id)))
            }
            Err(e) => Ok(error_result(e.to_string())),
        }
    }

    #[tool(description = "List open streams.")]
    async fn stream_list(&self, ctx: RequestContext<RoleServer>) -> CallToolResult {
        if let Err(r) = self.caller(&ctx) {
            return r;
        }
        let list = self.streams.list();
        if list.is_empty() {
            return text_result("no open streams".into());
        }
        let text = list
            .iter()
            .map(|s| {
                format!(
                    "{}\t{}\t{}s\t{} bytes pending\t{}",
                    s.id,
                    if s.running { "running" } else { "finished" },
                    s.age.as_secs(),
                    s.pending_bytes,
                    s.command
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        text_result(text)
    }
}

fn render_read(r: ReadResult, id: &str) -> String {
    let mut out = String::new();
    if r.dropped_bytes > 0 {
        let _ = writeln!(
            out,
            "[{} bytes dropped: buffer full, read more often]",
            r.dropped_bytes
        );
    }
    out.push_str(&r.data);
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    match r.finished {
        Some(Finished {
            outcome,
            exit_code,
            signal,
            stderr,
            error,
            duration,
        }) => {
            if let Some(e) = error {
                let _ = writeln!(out, "error: {e}");
            }
            if !stderr.is_empty() {
                let _ = write!(out, "--- stderr ---\n{stderr}");
            }
            let _ = write!(
                out,
                "[stream {id} finished: {}]",
                status_line(exit_code, signal, outcome, duration)
            );
        }
        None => {
            let _ = write!(
                out,
                "[stream {id} running; {} bytes still buffered]",
                r.pending_bytes
            );
        }
    }
    out
}

fn status_line(
    exit_code: Option<i32>,
    signal: Option<i32>,
    outcome: Option<Outcome>,
    duration: Duration,
) -> String {
    let mut parts = Vec::new();
    match (exit_code, signal) {
        (Some(c), _) => parts.push(format!("exit {c}")),
        (None, Some(s)) => parts.push(format!("killed by signal {s}")),
        _ => {}
    }
    match outcome {
        Some(Outcome::TimedOut) => parts.push("timed out".into()),
        Some(Outcome::Cancelled) => parts.push("cancelled".into()),
        Some(Outcome::OutputLimit) => parts.push("output truncated (limit reached)".into()),
        _ => {}
    }
    parts.push(format!("{}ms", duration.as_millis()));
    parts.join(", ")
}

#[tool_handler]
impl ServerHandler for LinuxMcp {
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(Implementation::new("linux-mcp", env!("CARGO_PKG_VERSION")))
            .with_instructions(
                "Restricted shell on a Linux server. Use `run` for commands and pipelines \
                 (e.g. `docker ps | grep postgres`), `stream_*` for follow output. \
                 Only allowlisted commands work; call `list_commands` first.",
            )
    }
}
