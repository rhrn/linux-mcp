use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use rmcp::ServiceExt;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::EnvFilter;

use linux_mcp::audit::{Audit, Caller};
use linux_mcp::config::Config;
use linux_mcp::exec::{self, ExecSpec};
use linux_mcp::mcp::{LinuxMcp, State};
use linux_mcp::policy::Policy;

/// Restricted-shell MCP server: stdio over SSH (default), or HTTP(S) with bearer keys (--http).
#[derive(Debug, Parser)]
#[command(version, about)]
struct Args {
    /// Path to the TOML config.
    #[arg(long, short, default_value = "/etc/linux-mcp/config.toml")]
    config: PathBuf,
    /// Validate the config, print the allowlist and exit.
    #[arg(long)]
    check_config: bool,
    /// Run one command through the policy and executor, print the result and exit (for testing).
    #[arg(long, value_name = "COMMAND")]
    exec: Option<String>,
    /// Skip the config ownership/permission check (development only).
    #[arg(long)]
    allow_insecure_config: bool,
    /// Identifier recorded in the audit log (set per key in authorized_keys). stdio only.
    #[arg(long)]
    client_id: Option<String>,
    /// Serve MCP over HTTP(S) using the [http] config section instead of stdio.
    #[arg(long, conflicts_with_all = ["exec", "client_id"])]
    http: bool,
    /// Generate a new HTTP bearer key for client ID, print it with its config entry and exit.
    #[arg(long, value_name = "ID", exclusive = true)]
    gen_key: Option<String>,
    /// Log filter (stderr), e.g. `info`, `linux_mcp=debug`. Overrides RUST_LOG.
    #[arg(long)]
    log: Option<String>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    if let Some(id) = &args.gen_key {
        let (token, hash) = linux_mcp::auth::generate_key();
        println!("# Give this token to the client (shown once; only its hash is stored):");
        println!("{token}\n");
        println!("# Add to the [http] section of the server config:");
        println!("[[http.keys]]\nid     = {id:?}\nsha256 = \"{hash}\"");
        return Ok(());
    }
    let filter = match &args.log {
        Some(f) => EnvFilter::new(f),
        None => EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn")),
    };
    // stdout carries the MCP protocol: logs must go to stderr.
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    let cfg = Config::load(&args.config, args.allow_insecure_config)?;
    let policy = Policy::new(&cfg)?;
    let missing = policy.missing_binaries();
    for (name, bin) in &missing {
        tracing::warn!(
            "commands.{name}: binary {} not found or not executable",
            bin.display()
        );
    }

    if args.check_config {
        if !missing.is_empty() {
            let list = missing
                .iter()
                .map(|(name, bin)| format!("  commands.{name}.binary = {}", bin.display()))
                .collect::<Vec<_>>()
                .join("\n");
            anyhow::bail!("binaries not found or not executable:\n{list}");
        }
        println!("config OK: {}\n", args.config.display());
        print!("{}", policy.describe());
        return Ok(());
    }

    let http = if args.http {
        Some(
            cfg.http
                .clone()
                .context("--http requires an [http] section in the config")?,
        )
    } else {
        None
    };
    let audit = Audit::new(cfg.server.audit_log.as_deref()).context("opening audit log")?;
    let state = Arc::new(State::new(policy, cfg.server, audit)?);

    if let Some(command) = args.exec {
        return exec_once(&state, &command).await;
    }

    if let Some(http) = http {
        let shutdown = CancellationToken::new();
        tokio::spawn({
            let shutdown = shutdown.clone();
            async move {
                wait_for_signal().await;
                tracing::info!("shutting down");
                shutdown.cancel();
            }
        });
        return linux_mcp::http::serve(state, &http, shutdown).await;
    }

    tracing::info!(config = %args.config.display(), "linux-mcp serving on stdio");
    let service = LinuxMcp::new(state, Caller::from_ssh_env(args.client_id))
        .serve(rmcp::transport::stdio())
        .await
        .context("MCP initialization failed")?;
    service.waiting().await?;
    Ok(())
}

async fn wait_for_signal() {
    use tokio::signal::unix::{SignalKind, signal};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = tokio::signal::ctrl_c() => {}
    }
}

async fn exec_once(state: &State, command: &str) -> anyhow::Result<()> {
    let (_, stages, cwd) = state
        .prepare(command, None)
        .map_err(|r| anyhow::anyhow!("denied: {r}"))?;
    let r = exec::run(
        ExecSpec {
            stages: &stages,
            cwd: &cwd,
            env: &state.env,
            timeout: Duration::from_secs(state.settings.default_timeout_s),
            stdout_cap: Some(state.settings.max_output_bytes),
            stderr_cap: state.settings.max_output_bytes,
        },
        CancellationToken::new(),
        None,
    )
    .await?;
    print!("{}", exec::clean_text(&r.stdout));
    eprint!("{}", exec::clean_text(&r.stderr));
    eprintln!(
        "[exit {:?}, {:?}, {}ms]",
        r.exit_code,
        r.outcome,
        r.duration.as_millis()
    );
    std::process::exit(r.exit_code.unwrap_or(1));
}
