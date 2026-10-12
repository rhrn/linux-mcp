# linux-mcp

A secure MCP server that runs **on a Linux host** and is reached **over SSH** (default) or
**over HTTP(S) with a secret key**. It gives an AI agent a restricted, shell-like interface:
only commands, subcommands and flags allowlisted in a config file can run, optionally joined
with pipes.

```
SSH:   MCP client ──ssh -T──► sshd ──forced command──► linux-mcp ──execve──► ls / grep / docker …
HTTP:  MCP client ──HTTPS + Bearer key──► linux-mcp --http ──execve──► …
```

- SSH mode: no network listener; MCP over stdio, SSH handles authentication and encryption.
- HTTP mode: Streamable HTTP on `/mcp`, bearer keys stored only as SHA-256 hashes, built-in TLS.
- No shell: the server parses the command line itself (quotes, escapes, `|`), rejects any
  other shell syntax, validates every pipeline stage, and runs binaries by absolute path
  with a cleared environment.
- Deny by default: unknown commands, subcommands, flags, bad flag values, and paths outside
  `allowed_paths` (symlinks resolved) are rejected.
- Limits: timeouts, output caps, concurrency caps; each pipeline runs in its own process group
  and is killed on timeout or MCP cancellation.
- JSONL audit log of every request (allowed or denied).

## Tools

| Tool | Purpose |
|------|---------|
| `run` | Run a command/pipeline, e.g. `docker ps \| grep postgres`. Streams output as progress notifications if the client sends a progress token. |
| `list_commands` | Show what's allowed. |
| `stream_start` / `stream_read` / `stream_stop` / `stream_list` | Background follow output, e.g. `docker logs -f web`. |

## Install (on the server)

```sh
# build: cargo zigbuild --release --target x86_64-unknown-linux-musl  (or grab a CI artifact)
sudo deploy/install.sh ./linux-mcp "$(cat ~/.ssh/id_ed25519.pub)" my-laptop
```

This creates an `mcp` system user, installs `/etc/linux-mcp/config.toml` (root-owned), and adds a
`restrict,command="…"` line to `~mcp/.ssh/authorized_keys` so the key can only start the server.
See `deploy/authorized_keys.example`.

Edit `/etc/linux-mcp/config.toml` to change what is allowed, then check it:

```sh
linux-mcp --config /etc/linux-mcp/config.toml --check-config
sudo -u mcp linux-mcp --exec 'docker ps | grep postgres'   # try a command without MCP
```

## Client config

```json
{
  "mcpServers": {
    "prod-box": {
      "command": "ssh",
      "args": ["-T", "-o", "BatchMode=yes", "mcp@prod-box"]
    }
  }
}
```

Claude Code: `claude mcp add prod-box -- ssh -T -o BatchMode=yes mcp@prod-box`

## HTTP mode (alternative to SSH)

1. Create a key per client. The token is printed once; only its hash goes in the config:

   ```sh
   linux-mcp --gen-key alice-laptop
   ```

2. Install (creates the `mcp` user, log dir and systemd unit; the SSH key is optional):

   ```sh
   sudo deploy/install.sh ./linux-mcp
   ```

   Add the `[http]` section (see `config/example.toml`) with `listen`, TLS cert/key and the
   `[[http.keys]]` entry to `/etc/linux-mcp/config.toml`, then start it:

   ```sh
   sudo systemctl enable --now linux-mcp-http
   journalctl -u linux-mcp-http -f
   ```

   If the service fails with `217/USER`, the `mcp` user is missing (run `install.sh`);
   `216/GROUP` means the `docker` group in `SupplementaryGroups=` doesn't exist;
   `226/NAMESPACE` means a sandboxing option failed (`journalctl -u linux-mcp-http` names it),
   usually a missing path or a container host (LXC/OpenVZ) without mount namespaces.

3. Client config (Claude Code expands `${VAR}` in `.mcp.json`):

   ```json
   {
     "mcpServers": {
       "prod-box": {
         "type": "http",
         "url": "https://prod-box.example.com:8765/mcp",
         "headers": { "Authorization": "Bearer ${LINUX_MCP_TOKEN}" }
       }
     }
   }
   ```

   or: `claude mcp add --transport http prod-box https://prod-box.example.com:8765/mcp --header "Authorization: Bearer $LINUX_MCP_TOKEN"`

HTTP-mode rules:
- Plain HTTP is refused on non-loopback addresses unless `allow_plaintext = true`
  (only for use behind a TLS-terminating reverse proxy).
- Every path requires a valid key (`401` otherwise). Tokens are compared by hash in constant time.
- The key id is recorded as `client_id` in the audit log, with the peer address as `remote`.
- Each MCP session is bound to the key that opened it, and streams are private to their session.
- To revoke a key, delete its `[[http.keys]]` entry and restart the service.

## Hermes Agent

[Hermes Agent](https://github.com/NousResearch/hermes-agent) reads MCP servers from
`~/.hermes/config.yaml` (`mcp_servers:`). Either transport works.

**HTTP(S)**: the token stays in the environment, and Hermes expands `${VAR}` in `headers`:

```yaml
mcp_servers:
  prod-box:
    url: "https://prod-box.example.com:8765/mcp"
    headers:
      Authorization: "Bearer ${LINUX_MCP_TOKEN}"
    timeout: 330            # > server.max_timeout_s, so long `run` calls aren't cut off
    connect_timeout: 30
    # ssl_verify: "/etc/ssl/linux-mcp-ca.pem"   # CA bundle if the server uses a self-signed cert
```

```sh
export LINUX_MCP_TOKEN=lmcp_...     # from `linux-mcp --gen-key hermes` on the server
```

**SSH**: Hermes starts `ssh` itself, and the server's forced command starts linux-mcp:

```yaml
mcp_servers:
  prod-box:
    command: "ssh"
    args: ["-T", "-o", "BatchMode=yes", "-i", "${userHome}/.ssh/id_ed25519_mcp", "mcp@prod-box.example.com"]
    timeout: 330
```

Restart Hermes (or run `/reload-mcp` in a session). The tools appear as
`mcp__prod_box__run`, `mcp__prod_box__list_commands`, `mcp__prod_box__stream_start`, ...
To expose only one-shot commands, add `tools: { include: [run, list_commands] }`.

## Security notes

- **Docker access is root-equivalent.** The `mcp` user is put in the `docker` group, so the
  docker subcommand/flag allowlist is the security boundary. Only read-only subcommands
  are in the example config. For a stronger boundary, run a read-only Docker socket proxy and
  set `server.env.DOCKER_HOST` to it instead of adding the user to the `docker` group.
- `awk` is GNU awk forced into `--sandbox` (`fixed_args`): no `system()`, no I/O redirection or
  pipes, no extensions, no adding files via `ARGV`. Never point it at mawk/BWK/busybox awk,
  which have no sandbox. `--check-config` reports a missing `/usr/bin/gawk`.
- `top` is forced into batch mode (`-b -n 1`); `top -c` and `docker inspect` can reveal
  secrets passed on command lines or in environment variables.
- `dmesg` usually needs root or `CAP_SYSLOG` (`kernel.dmesg_restrict=1`).
- `strace` can only attach to running processes (`strace -p PID`, no program arguments, no `-o`,
  no fault injection) and needs root or `CAP_SYS_PTRACE`. Traced syscalls reveal whatever the
  process reads or writes, including credentials: remove it if that matters.
- `journalctl` is forced to `--no-pager`, has no maintenance flags (vacuum/rotate/flush) and no
  `--file`/`-D`; it needs the `systemd-journal` group. Logs can contain secrets.
- `ip` is show-only (`ip a`, `ip route` with no further arguments); `ss` has no `-K`/`-D`/`-F`/`-N`.
  `ping`, `host` and `nslookup` let clients probe any network the server can reach.
- `docker inspect` shows container environment variables, which often contain secrets.
  Remove it from the config if that matters.
- Path checks happen before execution (check-then-use); `ls -L` and `grep -R` are left out of
  the example config because they follow symlinks during recursion.
- SSH vs HTTP: SSH mode has no listening port of its own and reuses your SSH key management.
  HTTP mode exposes a port; use TLS, a firewall, and one key per client.
- The config file must not be writable by the server user (enforced at startup unless
  `--allow-insecure-config`).

## Development

```sh
cargo test                     # unit + end-to-end tests over stdio and HTTP(S) (fake docker)
cargo clippy --all-targets -- -D warnings
cp config/example.toml /tmp/dev.toml   # edit workdir/allowed_paths
cargo run -- -c /tmp/dev.toml --allow-insecure-config --exec 'ls -la'
```
