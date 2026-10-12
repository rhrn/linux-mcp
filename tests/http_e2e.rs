//! Spawns the real binary with `--http` and speaks MCP (Streamable HTTP) to it.

mod common;

use std::io::{BufRead, BufReader};
use std::process::{Child, Command, Stdio};

use common::TestEnv;
use serde_json::{Value, json};

struct HttpServer {
    child: Child,
    url: String,
    env: TestEnv,
    alice: String,
    bob: String,
}

impl Drop for HttpServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// Start the server; `tls` = Some((cert_pem, key_pem)).
fn start(tls: Option<(String, String)>) -> HttpServer {
    let mut env = TestEnv::new();
    let (alice, alice_hash) = linux_mcp::auth::generate_key();
    let (bob, bob_hash) = linux_mcp::auth::generate_key();
    let mut http = toml::Table::new();
    http.insert("listen".into(), "127.0.0.1:0".into());
    let key = |id: &str, h: &str| {
        let mut t = toml::Table::new();
        t.insert("id".into(), id.into());
        t.insert("sha256".into(), h.into());
        toml::Value::Table(t)
    };
    http.insert(
        "keys".into(),
        toml::Value::Array(vec![key("alice", &alice_hash), key("bob", &bob_hash)]),
    );
    if let Some((cert, key)) = tls {
        let cert_path = env.root.join("cert.pem");
        let key_path = env.root.join("key.pem");
        std::fs::write(&cert_path, cert).unwrap();
        std::fs::write(&key_path, key).unwrap();
        http.insert("tls_cert".into(), cert_path.display().to_string().into());
        http.insert("tls_key".into(), key_path.display().to_string().into());
    }
    env.cfg.insert("http".into(), toml::Value::Table(http));
    let cfg_path = env.write_config();

    let mut child = Command::new(env!("CARGO_BIN_EXE_linux-mcp"))
        .args(["--http", "--allow-insecure-config", "--config"])
        .arg(&cfg_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stderr = BufReader::new(child.stderr.take().unwrap());
    let url = loop {
        let mut line = String::new();
        assert!(
            stderr.read_line(&mut line).unwrap() > 0,
            "server exited before listening"
        );
        if let Some(u) = line.trim().strip_prefix("linux-mcp listening on ") {
            break u.to_owned();
        }
    };
    // Keep draining stderr so the server never blocks on it.
    std::thread::spawn(move || for _ in stderr.lines() {});
    HttpServer {
        child,
        url,
        env,
        alice,
        bob,
    }
}

struct Session {
    client: reqwest::Client,
    url: String,
    token: String,
    session_id: Option<String>,
    protocol: Option<String>,
    next_id: u64,
}

/// Parse a JSON-RPC message out of a JSON or SSE response body.
fn parse_body(body: &str) -> Vec<Value> {
    if body.trim_start().starts_with('{') {
        return vec![serde_json::from_str(body).unwrap()];
    }
    body.lines()
        .filter_map(|l| l.strip_prefix("data:"))
        .filter(|d| !d.trim().is_empty())
        .filter_map(|d| serde_json::from_str(d.trim()).ok())
        .collect()
}

impl Session {
    fn new(url: &str, token: &str) -> Self {
        Self {
            client: reqwest::Client::new(),
            url: url.to_owned(),
            token: token.to_owned(),
            session_id: None,
            protocol: None,
            next_id: 1,
        }
    }

    async fn post(&self, body: Value) -> reqwest::Response {
        let mut req = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header("accept", "application/json, text/event-stream")
            .json(&body);
        if let Some(s) = &self.session_id {
            req = req.header("mcp-session-id", s);
        }
        if let Some(p) = &self.protocol {
            req = req.header("mcp-protocol-version", p);
        }
        req.send().await.unwrap()
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        let id = self.next_id;
        self.next_id += 1;
        let resp = self
            .post(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))
            .await;
        assert!(
            resp.status().is_success(),
            "{method}: HTTP {}",
            resp.status()
        );
        if let Some(sid) = resp.headers().get("mcp-session-id") {
            self.session_id = Some(sid.to_str().unwrap().to_owned());
        }
        let body = resp.text().await.unwrap();
        parse_body(&body)
            .into_iter()
            .find(|m| m["id"] == json!(id))
            .unwrap_or_else(|| panic!("no response for {method} in {body}"))
    }

    async fn initialize(&mut self) {
        let init = self
            .request(
                "initialize",
                json!({
                    "protocolVersion": "2025-06-18",
                    "capabilities": {},
                    "clientInfo": {"name": "http-e2e", "version": "0"}
                }),
            )
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "linux-mcp", "{init}");
        self.protocol = init["result"]["protocolVersion"]
            .as_str()
            .map(str::to_owned);
        let resp = self
            .post(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}))
            .await;
        assert!(resp.status().is_success(), "initialized: {}", resp.status());
    }

    async fn call(&mut self, tool: &str, args: Value) -> (String, bool) {
        let r = self
            .request("tools/call", json!({"name": tool, "arguments": args}))
            .await;
        let result = &r["result"];
        assert!(result.is_object(), "no result: {r}");
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        (text, result["isError"].as_bool().unwrap_or(false))
    }
}

#[tokio::test]
async fn rejects_missing_or_wrong_token() {
    let srv = start(None);
    let client = reqwest::Client::new();
    let body = json!({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}});

    let r = client.post(&srv.url).json(&body).send().await.unwrap();
    assert_eq!(r.status(), 401);
    assert_eq!(r.headers()["www-authenticate"], "Bearer");

    for bad in ["nope", "lmcp_0000", &srv.alice[..srv.alice.len() - 1]] {
        let r = client
            .post(&srv.url)
            .bearer_auth(bad)
            .json(&body)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), 401, "token {bad:?}");
    }
    // Any path is behind auth, not just /mcp.
    let base = srv.url.trim_end_matches("/mcp");
    let r = client.get(format!("{base}/other")).send().await.unwrap();
    assert_eq!(r.status(), 401);
}

#[tokio::test]
async fn runs_commands_and_audits_key_id() {
    let srv = start(None);
    let mut s = Session::new(&srv.url, &srv.alice);
    s.initialize().await;

    let (out, err) = s
        .call("run", json!({"command": "docker ps | grep postgres"}))
        .await;
    assert!(!err && out.starts_with("db postgres:16\n"), "{out}");

    let (out, err) = s.call("run", json!({"command": "ls /etc"})).await;
    assert!(err && out.starts_with("denied"), "{out}");

    let lines = srv.env.audit_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["client_id"], "alice");
    assert!(
        lines[0]["remote"]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:")
    );
    assert_eq!(lines[1]["decision"], "denied");
}

#[tokio::test]
async fn streams_are_per_session_and_sessions_per_key() {
    let srv = start(None);
    let mut a = Session::new(&srv.url, &srv.alice);
    a.initialize().await;
    let (out, err) = a
        .call("stream_start", json!({"command": "docker logs -f web"}))
        .await;
    assert!(!err, "{out}");
    let id = out
        .lines()
        .find_map(|l| l.strip_prefix("stream_id: "))
        .unwrap()
        .to_owned();

    // Another session (even with the same key) cannot see the stream.
    let mut a2 = Session::new(&srv.url, &srv.alice);
    a2.initialize().await;
    let (out, err) = a2.call("stream_read", json!({"stream_id": id})).await;
    assert!(err && out.contains("unknown stream"), "{out}");

    // Bob cannot use Alice's session id.
    let mut hijack = Session::new(&srv.url, &srv.bob);
    hijack.session_id = a.session_id.clone();
    hijack.protocol = a.protocol.clone();
    hijack.next_id = 100;
    let (out, err) = hijack.call("stream_read", json!({"stream_id": id})).await;
    assert!(err && out.contains("different client key"), "{out}");

    // Alice still can.
    let (out, err) = a
        .call("stream_read", json!({"stream_id": id, "wait_ms": 2000}))
        .await;
    assert!(!err && out.contains("log line"), "{out}");
    let (_, err) = a.call("stream_stop", json!({"stream_id": id})).await;
    assert!(!err);
}

#[test]
fn tls_with_curl() {
    let ck = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert = ck.cert.pem();
    let srv = start(Some((cert.clone(), ck.signing_key.serialize_pem())));
    assert!(srv.url.starts_with("https://127.0.0.1:"), "{}", srv.url);
    let port = srv.url.rsplit(':').next().unwrap().trim_end_matches("/mcp");
    let ca = srv.env.root.join("ca.pem");
    std::fs::write(&ca, cert).unwrap();

    let curl = |extra: &[&str], token: &str| {
        let out = Command::new("curl")
            .args(["-sS", "-o", "-", "-w", "\n%{http_code}", "--resolve"])
            .arg(format!("localhost:{port}:127.0.0.1"))
            .args(extra)
            .args(["-H", &format!("authorization: Bearer {token}")])
            .args(["-H", "content-type: application/json"])
            .args(["-H", "accept: application/json, text/event-stream"])
            .args(["-d", r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"curl","version":"0"}}}"#])
            .arg(format!("https://localhost:{port}/mcp"))
            .output()
            .expect("curl");
        String::from_utf8_lossy(&out.stdout).into_owned() + &String::from_utf8_lossy(&out.stderr)
    };

    let ok = curl(&["--cacert", ca.to_str().unwrap()], &srv.alice);
    assert!(
        ok.contains("\"linux-mcp\"") && ok.trim_end().ends_with("200"),
        "{ok}"
    );

    let unauth = curl(&["--cacert", ca.to_str().unwrap()], "wrong");
    assert!(unauth.trim_end().ends_with("401"), "{unauth}");

    // Without trusting the self-signed CA, the TLS handshake must fail.
    let untrusted = curl(&[], &srv.alice);
    assert!(
        untrusted.contains("\n000") && untrusted.contains("certificate"),
        "{untrusted}"
    );
}

#[test]
fn refuses_plaintext_on_public_address() {
    let mut env = TestEnv::new();
    let mut http = toml::Table::new();
    http.insert("listen".into(), "0.0.0.0:0".into());
    env.cfg.insert("http".into(), toml::Value::Table(http));
    let cfg_path = env.write_config();
    let out = Command::new(env!("CARGO_BIN_EXE_linux-mcp"))
        .args(["--http", "--allow-insecure-config", "--config"])
        .arg(&cfg_path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("not loopback"));
}

#[test]
fn refuses_http_without_keys() {
    let mut env = TestEnv::new();
    env.cfg
        .insert("http".into(), toml::Value::Table(toml::Table::new()));
    let cfg_path = env.write_config();
    let out = Command::new(env!("CARGO_BIN_EXE_linux-mcp"))
        .args(["--http", "--allow-insecure-config", "--config"])
        .arg(&cfg_path)
        .output()
        .unwrap();
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("http.keys is empty"));
}
