# PLAN — linux-mcp-via-ssh

A secure MCP server, written in Rust, that runs **on the target Linux host** and is reached
**over SSH** (stdio transport). It exposes a restricted, config-driven "shell" that can run
only allowlisted commands, with pipes and streaming output.

---

## 1. Architecture

```
 MCP client (Claude Code, etc.)
   │  spawns:  ssh -T mcp@host            ← SSH = transport, auth, encryption
   ▼
 sshd ── authorized_keys forced command ──► /usr/local/bin/linux-mcp --config /etc/linux-mcp/config.toml
                                               │  JSON-RPC over stdin/stdout
                                               ▼
                                   ┌─────────────────────────┐
                                   │ MCP layer (tools)       │
                                   │ parser → policy → exec  │
                                   └─────────────────────────┘
                                               │ execve (no /bin/sh)
                                               ▼
                                   /bin/ls, /usr/bin/grep, /usr/bin/docker …
```

Key decisions:
- **No network listener.** The binary only speaks MCP on stdio; SSH does auth + transport.
- **Forced command** in `authorized_keys` (`command="…",restrict`) — the key can do nothing
  except start the MCP server. No PTY, no port forwarding, no agent forwarding.
- **No real shell.** We tokenize the command line ourselves, validate every pipeline stage
  against the config, and `execve` binaries by absolute path, wiring stdout→stdin ourselves.
- **Dedicated unprivileged user** (`mcp`). Note: `docker` group membership is root-equivalent,
  so docker subcommand/flag allowlisting is a hard security boundary (see §6).

---

## 2. Tech stack (✅ acked)

| Concern            | Choice                                   | Why |
|--------------------|------------------------------------------|-----|
| Language           | Rust stable, edition 2024                | per AGENTS.md |
| MCP SDK            | `rmcp` (official Rust SDK), stdio transport | spec-compliant, tool macros, progress notifications |
| Async runtime      | `tokio` (process, io-util, time, signal) | async child processes, timeouts, streaming |
| Config             | `serde` + `toml`                         | human-editable, typed |
| Tool schemas       | `schemars` (via rmcp)                    | JSON Schema for tool inputs |
| Arg validation     | `regex`                                  | per-flag value patterns (e.g. container names) |
| Command-line parse | **own tokenizer** (small, no deps)       | full control: quotes + `\|` only, reject all other metachars |
| Errors             | `thiserror` (lib) + `anyhow` (main)      | standard |
| Logging / audit    | `tracing` + `tracing-subscriber` → stderr / file (JSON) | stdout is reserved for the protocol |
| CLI args           | `clap` (derive)                          | `--config`, `--check-config` |
| Docker access      | exec the **`docker` CLI**                | output identical to what users expect; no socket client needed |
| Tests              | built-in `#[test]` + `assert_cmd` + `insta` (snapshots) | parser/policy are pure → heavily unit-tested |
| Build / release    | static `x86_64` + `aarch64` musl binaries via `cargo-zigbuild` | single file drop-in on any distro |
| Lint / audit       | `clippy -D warnings`, `cargo-deny`, `cargo-audit` | supply-chain hygiene |

---

## 3. Command model

### 3.1 Supported syntax
- Words, single/double quotes, backslash escapes.
- Pipe `|` between stages: `docker ps | grep postgres`.
- **Rejected** (parse error): `;` `&&` `||` `&` `>` `<` `>>` `` ` `` `$(` `$VAR` `*`/`?` globs, `~`, newlines.
  (Globbing may be added later, resolved by us within allowed paths.)

### 3.2 Policy per stage
For each stage:
1. Command name must exist in config → mapped to an **absolute binary path**.
2. If the command defines subcommands (docker), the first positional must be an allowed subcommand.
3. Every flag must be allowlisted; combined short flags are expanded (`-la` → `-l -a`).
4. Flags that take values declare it; values may be checked by regex.
5. Positionals are checked by kind (`path`, `pattern`, `container`, `any`) with optional
   path-prefix restrictions (`allowed_paths`, canonicalized, no `..` escape).
6. Optional per-stage rule: e.g. `grep` only allowed as a pipe consumer, or also on files.

### 3.3 Config example (original sketch — see `config/example.toml` for the real, tested file)

```toml
[server]
workdir            = "/home/mcp"
max_output_bytes   = 1_048_576
default_timeout_s  = 30
max_timeout_s      = 300
allowed_paths      = ["/home/mcp", "/var/log", "/srv"]
audit_log          = "/var/log/linux-mcp/audit.jsonl"

[commands.pwd]
binary = "/bin/pwd"

[commands.ls]
binary     = "/bin/ls"
flags      = ["-l", "-a", "-h", "-t", "-r", "-R", "-1", "-d"]
positional = { kind = "path", max = 8 }

[commands.grep]
binary     = "/usr/bin/grep"
flags      = ["-i", "-v", "-n", "-c", "-E", "-F", "-w", "-o", "-r"]
value_flags = { "-A" = '^\d{1,4}$', "-B" = '^\d{1,4}$', "-C" = '^\d{1,4}$', "-m" = '^\d{1,6}$', "-e" = '.*' }
positional = { kind = "pattern_then_paths", max = 8 }

[commands.docker]
binary = "/usr/bin/docker"

  [commands.docker.subcommands.ps]
  flags       = ["-a", "--all", "-q", "--no-trunc", "-s"]
  value_flags = { "--format" = '.*', "--filter" = '^[a-z_]+=[\w.\-/:]+$', "-n" = '^\d+$' }

  [commands.docker.subcommands.images]
  flags       = ["-a", "-q", "--no-trunc", "--digests"]
  value_flags = { "--format" = '.*', "--filter" = '^[a-z_]+=[\w.\-/:]+$' }

  [commands.docker.subcommands.logs]
  flags       = ["-f", "--follow", "-t", "--timestamps"]
  value_flags = { "--tail" = '^(\d+|all)$', "--since" = '^[\w.:\-]+$', "--until" = '^[\w.:\-]+$' }
  positional  = { kind = "container", min = 1, max = 1 }
  streaming   = true                       # -f allowed; bounded by timeout/output caps

  [commands.docker.subcommands.inspect]
  value_flags = { "--format" = '.*', "--type" = '^(container|image|volume|network)$' }
  positional  = { kind = "container", min = 1, max = 8 }

  [commands.docker.subcommands.events]
  value_flags = { "--since" = '^[\w.:\-]+$', "--until" = '^[\w.:\-]+$', "--filter" = '^[a-z_]+=[\w.\-/:]+$', "--format" = '.*' }
  streaming   = true

  [commands.docker.subcommands.history]
  flags       = ["-H", "--no-trunc", "-q"]
  value_flags = { "--format" = '.*' }
  positional  = { kind = "container", min = 1, max = 1 }
```

`kind = "container"` → regex `^[a-zA-Z0-9][a-zA-Z0-9_.\-:/@]*$` (names, IDs, image refs).

---

## 4. MCP surface

| Tool              | Input                                            | Output |
|-------------------|--------------------------------------------------|--------|
| `run`             | `command: string`, `timeout_s?: u32`, `cwd?: string` | stdout, stderr, exit code, `truncated`, `timed_out` |
| `list_commands`   | –                                                | allowlist rendered from config (so the model knows what's allowed) |
| `stream_start`    | `command`, `max_duration_s?`                      | `stream_id` |
| `stream_read`     | `stream_id`, `max_bytes?`                        | new output chunk since last read, `finished` |
| `stream_stop`     | `stream_id`                                      | final status |

Streaming (`docker logs -f`, `docker events`):
- Via `run`: output is sent incrementally as MCP **progress notifications** (when the client
  supplies a progress token) and the call returns when timeout / output cap is reached.
- Via `stream_*`: background session with a ring buffer, for clients that don't render
  progress. Max concurrent streams and idle TTL configurable.

---

## 5. Execution details
- `tokio::process::Command` per stage, `env_clear()` + minimal `PATH`, `LANG=C.UTF-8`.
- Stages connected with OS pipes; only last stage's stdout + all stderr captured.
- Each pipeline in its own **process group**; on timeout/cancel → `SIGTERM`, grace, `SIGKILL`.
- Output capped (`max_output_bytes`), UTF-8 lossy, ANSI escapes stripped.
- MCP cancellation (`notifications/cancelled`) kills the pipeline.
- `stdin` of first stage = `/dev/null`.
- Concurrency limit on simultaneous pipelines.

---

## 6. Security checklist
- [x] Forced command + `restrict` in `authorized_keys` (root-owned); dedicated `mcp` user.
      (Login shell must be `/bin/sh`: sshd runs forced commands through it.)
- [x] No shell interpreter anywhere; absolute binary paths only.
- [x] Deny-by-default: unknown command / subcommand / flag → reject with clear reason.
- [x] Docker: only read-only subcommands; no `exec`, `run`, `cp`, `--privileged`, etc. (never in allowlist).
      Optional: point `DOCKER_HOST` at a read-only socket proxy (e.g. tecnativa/docker-socket-proxy).
- [x] Path args canonicalized & confined to `allowed_paths`; symlink escape checked.
- [x] Resource limits: timeout, output cap, concurrency cap. [ ] optional `setrlimit` (CPU, NOFILE).
- [x] Audit log (JSONL): timestamp, `--client-id` (per key), `SSH_CONNECTION`, command, decision, exit code, duration.
- [x] Config file owned by root, not writable by `mcp`; refuse to start if permissions are loose.
- [ ] Later: Landlock / seccomp sandboxing for spawned processes.

---

## 7. Project layout

```
Cargo.toml
src/
  main.rs        # clap args, logging, start rmcp stdio server
  config.rs      # serde types, load + validate (--check-config)
  parser.rs      # tokenizer → Pipeline { stages: Vec<Vec<String>> }
  policy.rs      # validate Pipeline against config → ValidatedPipeline
  exec.rs        # spawn pipeline, timeouts, caps, process groups
  stream.rs      # background stream sessions (ring buffer)
  mcp.rs         # tool handlers (run, list_commands, stream_*)
  http.rs        # HTTP(S) transport (axum + rmcp streamable HTTP)
  auth.rs        # bearer keys: generation, hashing, middleware
  audit.rs       # JSONL audit log
config/example.toml
deploy/
  authorized_keys.example
  install.sh
tests/
  parser.rs  policy.rs  e2e.rs   # e2e: spawn binary, speak MCP over stdio
```

---

## 8. Milestones

| # | Milestone | Done when | Status |
|---|-----------|-----------|--------|
| M0 | Scaffold: cargo project, CI (fmt, clippy, test, deny), example config | `cargo test` green in CI | ✅ (CI not yet run on GitHub) |
| M1 | Config + parser + policy (pure logic) | table-driven tests incl. all AGENTS.md examples + injection attempts rejected | ✅ |
| M2 | Executor: pipelines, timeouts, output caps, kill on cancel | `ls -la`, `docker ps \| grep postgres` work locally | ✅ (verified vs. real docker) |
| M3 | MCP layer with `rmcp`: `run`, `list_commands` | works from Claude Code via `ssh` | ✅ (e2e over stdio) |
| M4 | Streaming: progress notifications + `stream_*` tools | `docker logs -f {container}` streams, stops cleanly | ✅ |
| M5 | Audit log, hardening, permission checks | security checklist items ticked | ✅ except setrlimit / Landlock / seccomp |
| M6 | Release: musl static builds, install script, README with client config | one-command install on a fresh host | ✅ |

Implementation notes (deviations from the sketch above):
- Streaming config key `streaming = true` was dropped: every pipeline is bounded by timeout and
  output caps, so follow flags (`-f`) are just ordinary allowlisted flags.
- `stream_list` tool added; `stream_read` takes `wait_ms` for long-polling.
- Exit code reported is the last stage's (like `sh` without `pipefail`); stderr of every stage
  is captured and labeled `[name]` in pipelines.

Client config (README):

```json
{
  "mcpServers": {
    "prod-box": { "command": "ssh", "args": ["-T", "-o", "BatchMode=yes", "mcp@prod-box"] }
  }
}
```

---

## 8a. Default command set (phase 1.5)

Added to `config/example.toml`: `cat`, `awk` (gawk `--sandbox`), `top` (`-b -n 1`), `dmesg`
(read-only flags), `df`, `free`, `swapon` (display only). New config key `fixed_args`: arguments
always inserted after the binary, which the client cannot remove or override.

Then: `journalctl` (`--no-pager`), `uptime`, `uname`, `ps` (UNIX-style options), `vmstat`,
`strace` (attach-only: `-p PID`), `du`, `lsblk`, `ping`, `ss`, `ip` (show-only `a`/`route`),
`nslookup`, `host`, `head`, `tail` (no `-F`/`--follow=name`/`--retry`).

## 8b. HTTP transport (added after phase 1)

Alternative to SSH for clients that can't spawn `ssh`: `linux-mcp --http`.

| Concern | Decision |
|---------|----------|
| Transport | rmcp Streamable HTTP server at `/mcp`, served by `axum` + `axum-server` |
| Auth | `Authorization: Bearer lmcp_<64 hex>`; config stores `[[http.keys]] id + sha256` only; constant-time compare; all paths behind auth |
| Key generation | `linux-mcp --gen-key <id>` (32 bytes from OS RNG) |
| TLS | built in (`rustls` with the `ring` provider, PEM cert/key); plaintext refused off-loopback unless `allow_plaintext` |
| Host header | rmcp loopback allowlist when listening on loopback; configurable `allowed_hosts` otherwise |
| Identity | key id → `client_id`, peer addr → `remote` in audit log |
| Isolation | one `LinuxMcp` (and stream set) per MCP session; session bound to the key that created it |
| Ops | `deploy/linux-mcp-http.service` (systemd, hardened); graceful shutdown on SIGTERM kills running children |

Not done: rate limiting of failed auth (keys are 256-bit, so brute force is not practical; failures are logged),
cap on number of HTTP sessions per key, key rotation without restart (SIGHUP reload).

## 9. Out of scope (phase 1) / later
- Commands beyond the phase-1 list (`cat`, `tail`, `journalctl`, `systemctl status`, `df`, …) — config-only additions.
- Glob expansion, `cd` / session-persistent cwd.
- Multiple named profiles per SSH key.
- Landlock/seccomp sandbox.
