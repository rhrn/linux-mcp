//! Spawns the real binary and speaks MCP (JSON-RPC over stdio) to it.

mod common;

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};

use common::TestEnv;
use serde_json::{Value, json};

struct Server {
    child: Child,
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
    next_id: u64,
    env: TestEnv,
}

impl Server {
    fn start() -> Self {
        let env = TestEnv::new();
        let cfg_path = env.write_config();

        let mut child = Command::new(env!("CARGO_BIN_EXE_linux-mcp"))
            .args(["--allow-insecure-config", "--client-id", "e2e", "--config"])
            .arg(&cfg_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdin = child.stdin.take().unwrap();
        let stdout = BufReader::new(child.stdout.take().unwrap());
        let mut s = Server {
            child,
            stdin,
            stdout,
            next_id: 1,
            env,
        };
        let init = s.request(
            "initialize",
            json!({
                "protocolVersion": "2025-06-18",
                "capabilities": {},
                "clientInfo": {"name": "e2e", "version": "0"}
            }),
        );
        assert_eq!(init["result"]["serverInfo"]["name"], "linux-mcp", "{init}");
        s.send(json!({"jsonrpc": "2.0", "method": "notifications/initialized"}));
        s
    }

    fn send(&mut self, msg: Value) {
        writeln!(self.stdin, "{msg}").unwrap();
        self.stdin.flush().unwrap();
    }

    /// Send a request; collect notifications until the matching response.
    fn request_with_notes(&mut self, method: &str, params: Value) -> (Value, Vec<Value>) {
        let id = self.next_id;
        self.next_id += 1;
        self.send(json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}));
        let mut notes = Vec::new();
        loop {
            let mut line = String::new();
            assert!(
                self.stdout.read_line(&mut line).unwrap() > 0,
                "server closed stdout"
            );
            let msg: Value = serde_json::from_str(&line).unwrap();
            if msg["id"] == json!(id) {
                return (msg, notes);
            }
            notes.push(msg);
        }
    }

    fn request(&mut self, method: &str, params: Value) -> Value {
        self.request_with_notes(method, params).0
    }

    /// Call a tool, return (text, is_error).
    fn call(&mut self, tool: &str, args: Value) -> (String, bool) {
        let r = self.request("tools/call", json!({"name": tool, "arguments": args}));
        let result = &r["result"];
        assert!(result.is_object(), "no result: {r}");
        let text = result["content"][0]["text"]
            .as_str()
            .unwrap_or_default()
            .to_owned();
        (text, result["isError"].as_bool().unwrap_or(false))
    }

    fn run(&mut self, command: &str) -> (String, bool) {
        self.call("run", json!({"command": command}))
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn tools_are_listed() {
    let mut s = Server::start();
    let r = s.request("tools/list", json!({}));
    let names: Vec<&str> = r["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].as_str().unwrap())
        .collect();
    for t in [
        "run",
        "list_commands",
        "stream_start",
        "stream_read",
        "stream_stop",
        "stream_list",
    ] {
        assert!(names.contains(&t), "missing {t} in {names:?}");
    }
    let (text, _) = s.call("list_commands", json!({}));
    assert!(text.contains("docker logs"), "{text}");
}

#[test]
fn agents_md_examples() {
    let mut s = Server::start();

    let (out, err) = s.run("ls -la");
    assert!(
        !err && out.contains("app.log") && out.contains("[exit 0"),
        "{out}"
    );

    let (out, err) = s.run("pwd");
    assert!(!err && out.contains("/data\n"), "{out}");

    let (out, err) = s.run("docker ps | grep postgres");
    assert!(!err, "{out}");
    assert!(
        out.starts_with("db postgres:16\n") && !out.contains("nginx"),
        "{out}"
    );

    let (out, err) = s.run("grep -n postgres app.log");
    assert!(!err && out.starts_with("2:postgres ready"), "{out}");

    let (out, err) = s.call(
        "run",
        json!({"command": "docker logs -f db", "timeout_s": 1}),
    );
    assert!(
        !err && out.contains("log line") && out.contains("timed out"),
        "{out}"
    );
}

#[test]
fn denials_are_tool_errors() {
    let mut s = Server::start();
    for cmd in [
        "rm -rf /",
        "ls; id",
        "ls $(id)",
        "ls /etc",
        "ls ..",
        "grep root /etc/passwd",
        "docker exec db sh",
        "docker run --privileged alpine",
        "ls -la | sh",
    ] {
        let (out, err) = s.run(cmd);
        assert!(err && out.starts_with("denied: "), "{cmd}: {out}");
    }
    let (out, err) = s.call("run", json!({"command": "ls", "cwd": "/"}));
    assert!(err && out.contains("cwd"), "{out}");
}

#[test]
fn progress_notifications_stream_output() {
    let mut s = Server::start();
    let (resp, notes) = s.request_with_notes(
        "tools/call",
        json!({
            "name": "run",
            "arguments": {"command": "docker logs -f web", "timeout_s": 1},
            "_meta": {"progressToken": "tok-1"}
        }),
    );
    assert!(
        resp["result"]["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("log line")
    );
    let progress: Vec<_> = notes
        .iter()
        .filter(|n| n["method"] == "notifications/progress")
        .collect();
    assert!(!progress.is_empty(), "no progress notifications: {notes:?}");
    assert_eq!(progress[0]["params"]["progressToken"], "tok-1");
    assert!(
        progress[0]["params"]["message"]
            .as_str()
            .unwrap()
            .contains("log line")
    );
}

#[test]
fn stream_lifecycle() {
    let mut s = Server::start();
    let (out, err) = s.call("stream_start", json!({"command": "docker logs -f web"}));
    assert!(!err, "{out}");
    let id = out
        .lines()
        .find_map(|l| l.strip_prefix("stream_id: "))
        .unwrap()
        .to_owned();

    let (out, err) = s.call("stream_read", json!({"stream_id": id, "wait_ms": 2000}));
    assert!(
        !err && out.contains("log line") && out.contains("running"),
        "{out}"
    );

    let (out, _) = s.call("stream_list", json!({}));
    assert!(out.contains(&id), "{out}");

    let (out, err) = s.call("stream_stop", json!({"stream_id": id}));
    assert!(!err && out.contains("finished"), "{out}");

    let (out, err) = s.call("stream_read", json!({"stream_id": id}));
    assert!(err && out.contains("unknown stream"), "{out}");

    let (out, err) = s.call("stream_start", json!({"command": "docker exec web sh"}));
    assert!(err && out.starts_with("denied"), "{out}");
}

#[test]
fn audit_log_written() {
    let mut s = Server::start();
    s.run("pwd");
    s.run("rm -rf /");
    let lines = s.env.audit_lines();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["decision"], "allowed");
    assert_eq!(lines[0]["client_id"], "e2e");
    assert_eq!(lines[0]["exit_code"], 0);
    assert_eq!(lines[1]["decision"], "denied");
    assert_eq!(lines[1]["command"], "rm -rf /");
}
