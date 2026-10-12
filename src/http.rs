//! Streamable HTTP transport with bearer-token auth and optional TLS.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use rmcp::transport::streamable_http_server::{StreamableHttpServerConfig, StreamableHttpService};
use tokio_util::sync::CancellationToken;

use crate::audit::Caller;
use crate::auth::{KeyStore, require_bearer};
use crate::config::HttpSettings;
use crate::mcp::{LinuxMcp, State};

/// MCP endpoint path.
pub const MCP_PATH: &str = "/mcp";

/// Serve MCP over HTTP(S) until `shutdown` is cancelled.
pub async fn serve(
    state: Arc<State>,
    http: &HttpSettings,
    shutdown: CancellationToken,
) -> anyhow::Result<()> {
    let keys = Arc::new(KeyStore::new(&http.keys)?);

    let mut mcp_config =
        StreamableHttpServerConfig::default().with_cancellation_token(shutdown.child_token());
    if !http.allowed_hosts.is_empty() {
        mcp_config = mcp_config.with_allowed_hosts(http.allowed_hosts.clone());
    } else if !http.listen.ip().is_loopback() {
        // Host checks defend unauthenticated local servers against DNS rebinding;
        // here every request needs a bearer token, so an unset list means "any host".
        mcp_config = mcp_config.disable_allowed_hosts();
    }

    let mcp = StreamableHttpService::new(
        move || Ok(LinuxMcp::new(state.clone(), Caller::default())),
        Arc::new(LocalSessionManager::default()),
        mcp_config,
    );
    let app = Router::new()
        .route_service(MCP_PATH, mcp)
        .layer(axum::middleware::from_fn_with_state(keys, require_bearer))
        .into_make_service_with_connect_info::<SocketAddr>();

    let handle: Handle<SocketAddr> = Handle::new();
    tokio::spawn({
        let handle = handle.clone();
        let shutdown = shutdown.clone();
        async move {
            shutdown.cancelled().await;
            handle.graceful_shutdown(Some(Duration::from_secs(5)));
        }
    });
    tokio::spawn({
        let handle = handle.clone();
        let scheme = if http.tls_cert.is_some() {
            "https"
        } else {
            "http"
        };
        async move {
            if let Some(addr) = handle.listening().await {
                // Logged unconditionally: with port 0 this is the only way to learn the port.
                eprintln!("linux-mcp listening on {scheme}://{addr}{MCP_PATH}");
            }
        }
    });

    match (&http.tls_cert, &http.tls_key) {
        (Some(cert), Some(key)) => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls = RustlsConfig::from_pem_file(cert, key)
                .await
                .with_context(|| {
                    format!(
                        "loading TLS cert {} / key {}",
                        cert.display(),
                        key.display()
                    )
                })?;
            axum_server::bind_rustls(http.listen, tls)
                .handle(handle)
                .serve(app)
                .await
        }
        _ => {
            axum_server::bind(http.listen)
                .handle(handle)
                .serve(app)
                .await
        }
    }
    .with_context(|| format!("HTTP server on {}", http.listen))
}
