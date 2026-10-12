//! Validates parsed pipelines against the configured allowlist.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use regex::Regex;

use crate::config::{ArgRules, Config, ConfigError, PositionalKind};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    #[error("command '{0}' is not allowed (see list_commands)")]
    UnknownCommand(String),
    #[error("'{cmd}' requires a subcommand, one of: {allowed}")]
    MissingSubcommand { cmd: String, allowed: String },
    #[error("'{cmd} {sub}' is not allowed; allowed subcommands: {allowed}")]
    UnknownSubcommand {
        cmd: String,
        sub: String,
        allowed: String,
    },
    #[error("{ctx}: flag '{flag}' is not allowed")]
    UnknownFlag { ctx: String, flag: String },
    #[error("{ctx}: flag '{flag}' requires a value")]
    MissingValue { ctx: String, flag: String },
    #[error("{ctx}: flag '{flag}' does not take a value")]
    UnexpectedValue { ctx: String, flag: String },
    #[error("{ctx}: value {value:?} for '{flag}' is not allowed")]
    BadValue {
        ctx: String,
        flag: String,
        value: String,
    },
    #[error("{ctx}: expected {min}..={max} arguments, got {got}")]
    PositionalCount {
        ctx: String,
        min: usize,
        max: usize,
        got: usize,
    },
    #[error("{ctx}: {value:?} is not a valid container/image reference")]
    BadContainer { ctx: String, value: String },
    #[error("{ctx}: path {path:?} is not accessible (missing or outside allowed paths)")]
    PathDenied { ctx: String, path: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Stage {
    /// Command name as configured (`ls`, `docker`, ...).
    pub name: String,
    pub binary: PathBuf,
    /// Arguments, excluding argv[0].
    pub args: Vec<String>,
}

#[derive(Debug)]
struct CompiledRules {
    flags: Vec<String>,
    value_flags: BTreeMap<String, Regex>,
    kind: PositionalKind,
    min: usize,
    max: usize,
}

#[derive(Debug)]
struct CompiledCommand {
    binary: PathBuf,
    description: Option<String>,
    fixed_args: Vec<String>,
    rules: CompiledRules,
    subcommands: BTreeMap<String, CompiledRules>,
}

#[derive(Debug)]
pub struct Policy {
    commands: BTreeMap<String, CompiledCommand>,
    allowed_paths: Vec<PathBuf>,
    container_re: Regex,
}

impl Policy {
    pub fn new(cfg: &Config) -> Result<Self, ConfigError> {
        let mut commands = BTreeMap::new();
        for (name, spec) in &cfg.commands {
            let rules = compile_rules(name, &spec.rules)?;
            let mut subcommands = BTreeMap::new();
            for (sub, r) in &spec.subcommands {
                subcommands.insert(sub.clone(), compile_rules(&format!("{name}.{sub}"), r)?);
            }
            commands.insert(
                name.clone(),
                CompiledCommand {
                    binary: spec.binary.clone(),
                    description: spec.description.clone(),
                    fixed_args: spec.fixed_args.clone(),
                    rules,
                    subcommands,
                },
            );
        }
        // Canonicalize so symlinked prefixes (e.g. /var -> /private/var) compare correctly.
        // Paths that don't exist are kept as-is; nothing can resolve into them anyway.
        let allowed_paths = cfg
            .server
            .allowed_paths
            .iter()
            .map(|p| p.canonicalize().unwrap_or_else(|_| p.clone()))
            .collect();
        Ok(Self {
            commands,
            allowed_paths,
            container_re: Regex::new(r"^[A-Za-z0-9][A-Za-z0-9_.\-:/@]{0,254}$").unwrap(),
        })
    }

    /// Validate a whole pipeline. `cwd` must already be an allowed, canonical directory.
    pub fn check(&self, pipeline: &[Vec<String>], cwd: &Path) -> Result<Vec<Stage>, PolicyError> {
        pipeline
            .iter()
            .map(|argv| self.check_stage(argv, cwd))
            .collect()
    }

    /// Resolve and confine a working directory.
    pub fn check_cwd(&self, cwd: &Path, base: &Path) -> Result<PathBuf, PolicyError> {
        let resolved = self.resolve_path(&cwd.to_string_lossy(), base, "cwd")?;
        if !resolved.is_dir() {
            return Err(PolicyError::PathDenied {
                ctx: "cwd".into(),
                path: cwd.display().to_string(),
            });
        }
        Ok(resolved)
    }

    fn check_stage(&self, argv: &[String], cwd: &Path) -> Result<Stage, PolicyError> {
        let name = &argv[0];
        let cmd = self
            .commands
            .get(name)
            .ok_or_else(|| PolicyError::UnknownCommand(name.clone()))?;
        let mut args = &argv[1..];
        let (rules, ctx) = if cmd.subcommands.is_empty() {
            (&cmd.rules, name.clone())
        } else {
            let allowed = cmd
                .subcommands
                .keys()
                .cloned()
                .collect::<Vec<_>>()
                .join(", ");
            let Some(sub) = args.first() else {
                return Err(PolicyError::MissingSubcommand {
                    cmd: name.clone(),
                    allowed,
                });
            };
            let rules = cmd
                .subcommands
                .get(sub)
                .ok_or_else(|| PolicyError::UnknownSubcommand {
                    cmd: name.clone(),
                    sub: sub.clone(),
                    allowed,
                })?;
            args = &args[1..];
            (rules, format!("{name} {sub}"))
        };
        self.check_args(rules, &ctx, args, cwd)?;
        Ok(Stage {
            name: name.clone(),
            binary: cmd.binary.clone(),
            args: cmd.fixed_args.iter().chain(&argv[1..]).cloned().collect(),
        })
    }

    fn check_args(
        &self,
        rules: &CompiledRules,
        ctx: &str,
        args: &[String],
        cwd: &Path,
    ) -> Result<(), PolicyError> {
        let mut positionals: Vec<&str> = Vec::new();
        let mut used_value_flags: Vec<&str> = Vec::new();
        let mut i = 0;
        let mut only_positional = false;

        while i < args.len() {
            let arg = args[i].as_str();
            i += 1;
            if only_positional || arg == "-" || !arg.starts_with('-') {
                positionals.push(arg);
                continue;
            }
            if arg == "--" {
                only_positional = true;
                continue;
            }

            if let Some(long) = arg.strip_prefix("--") {
                let (flag, inline) = match long.split_once('=') {
                    Some((f, v)) => (format!("--{f}"), Some(v)),
                    None => (arg.to_owned(), None),
                };
                if rules.flags.contains(&flag) {
                    if inline.is_some() {
                        return Err(PolicyError::UnexpectedValue {
                            ctx: ctx.into(),
                            flag,
                        });
                    }
                } else if let Some(re) = rules.value_flags.get(&flag) {
                    let value = match inline {
                        Some(v) => v,
                        None => next_value(args, &mut i, ctx, &flag)?,
                    };
                    check_value(re, ctx, &flag, value)?;
                    used_value_flags.push(rules.value_flags.get_key_value(&flag).unwrap().0);
                } else {
                    return Err(PolicyError::UnknownFlag {
                        ctx: ctx.into(),
                        flag,
                    });
                }
                continue;
            }

            // Short flag(s): `-l`, `-la`, `-A3`, `-n 5`.
            let body = &arg[1..];
            for (pos, c) in body.char_indices() {
                let flag = format!("-{c}");
                if rules.flags.contains(&flag) {
                    continue;
                }
                if let Some(re) = rules.value_flags.get(&flag) {
                    let rest = &body[pos + c.len_utf8()..];
                    let value = if rest.is_empty() {
                        next_value(args, &mut i, ctx, &flag)?
                    } else {
                        rest
                    };
                    check_value(re, ctx, &flag, value)?;
                    used_value_flags.push(rules.value_flags.get_key_value(&flag).unwrap().0);
                    break;
                }
                return Err(PolicyError::UnknownFlag {
                    ctx: ctx.into(),
                    flag,
                });
            }
        }

        if positionals.len() < rules.min || positionals.len() > rules.max {
            return Err(PolicyError::PositionalCount {
                ctx: ctx.into(),
                min: rules.min,
                max: rules.max,
                got: positionals.len(),
            });
        }

        match rules.kind {
            PositionalKind::Any => {}
            PositionalKind::Path => {
                for p in positionals {
                    self.check_path(p, cwd, ctx)?;
                }
            }
            PositionalKind::PatternThenPaths => {
                let pattern_by_flag = used_value_flags
                    .iter()
                    .any(|f| matches!(*f, "-e" | "--regexp"));
                let paths = if pattern_by_flag {
                    &positionals[..]
                } else {
                    positionals.get(1..).unwrap_or(&[])
                };
                for p in paths {
                    self.check_path(p, cwd, ctx)?;
                }
            }
            PositionalKind::Container => {
                for p in positionals {
                    if !self.container_re.is_match(p) {
                        return Err(PolicyError::BadContainer {
                            ctx: ctx.into(),
                            value: p.into(),
                        });
                    }
                }
            }
        }
        Ok(())
    }

    fn check_path(&self, p: &str, cwd: &Path, ctx: &str) -> Result<(), PolicyError> {
        if p == "-" {
            return Ok(()); // stdin
        }
        self.resolve_path(p, cwd, ctx).map(|_| ())
    }

    /// Canonicalize `p` (relative to `base`) and require it to be inside an allowed path.
    /// Symlinks are resolved, so links pointing outside are rejected.
    fn resolve_path(&self, p: &str, base: &Path, ctx: &str) -> Result<PathBuf, PolicyError> {
        let denied = || PolicyError::PathDenied {
            ctx: ctx.into(),
            path: p.into(),
        };
        let joined = base.join(p);
        let canon = joined.canonicalize().map_err(|_| denied())?;
        if self.allowed_paths.iter().any(|a| canon.starts_with(a)) {
            Ok(canon)
        } else {
            Err(denied())
        }
    }

    /// Configured binaries that don't exist or aren't executable files on this host.
    pub fn missing_binaries(&self) -> Vec<(String, PathBuf)> {
        use std::os::unix::fs::PermissionsExt;
        self.commands
            .iter()
            .filter(|(_, c)| {
                !std::fs::metadata(&c.binary)
                    .is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            })
            .map(|(name, c)| (name.clone(), c.binary.clone()))
            .collect()
    }

    /// Human/LLM-readable description of everything that is allowed.
    pub fn describe(&self) -> String {
        let mut out = String::new();
        let _ = writeln!(
            out,
            "Allowed commands (combine with '|'; no other shell syntax). Path arguments must be inside: {}",
            self.allowed_paths
                .iter()
                .map(|p| p.display().to_string())
                .collect::<Vec<_>>()
                .join(", ")
        );
        for (name, cmd) in &self.commands {
            let _ = write!(out, "\n{name}");
            if let Some(d) = &cmd.description {
                let _ = write!(out, " — {d}");
            }
            out.push('\n');
            if !cmd.fixed_args.is_empty() {
                let _ = writeln!(out, "  always runs with: {}", cmd.fixed_args.join(" "));
            }
            if cmd.subcommands.is_empty() {
                describe_rules(&mut out, "  ", &cmd.rules);
            } else {
                for (sub, r) in &cmd.subcommands {
                    let _ = writeln!(out, "  {name} {sub}");
                    describe_rules(&mut out, "    ", r);
                }
            }
        }
        out
    }
}

fn describe_rules(out: &mut String, indent: &str, r: &CompiledRules) {
    if !r.flags.is_empty() {
        let _ = writeln!(out, "{indent}flags: {}", r.flags.join(" "));
    }
    if !r.value_flags.is_empty() {
        let vf = r
            .value_flags
            .iter()
            .map(|(k, re)| {
                let pat = re.as_str();
                let pat = pat
                    .strip_prefix("^(?:")
                    .and_then(|s| s.strip_suffix(")$"))
                    .unwrap_or(pat);
                format!("{k} <{pat}>")
            })
            .collect::<Vec<_>>();
        let _ = writeln!(out, "{indent}value flags: {}", vf.join(", "));
    }
    if r.max > 0 {
        let kind = match r.kind {
            PositionalKind::Path => "path",
            PositionalKind::PatternThenPaths => "pattern [path...]",
            PositionalKind::Container => "container/image",
            PositionalKind::Any => "any",
        };
        let _ = writeln!(out, "{indent}arguments: {kind} ({}..={})", r.min, r.max);
    }
}

fn compile_rules(ctx: &str, r: &ArgRules) -> Result<CompiledRules, ConfigError> {
    let mut value_flags = BTreeMap::new();
    for (flag, pat) in &r.value_flags {
        if r.flags.contains(flag) {
            return Err(ConfigError::Invalid(format!(
                "commands.{ctx}: '{flag}' is both a flag and a value flag"
            )));
        }
        // Anchor: the whole value must match.
        let re = Regex::new(&format!("^(?:{pat})$")).map_err(|e| {
            ConfigError::Invalid(format!("commands.{ctx}: bad regex for '{flag}': {e}"))
        })?;
        value_flags.insert(flag.clone(), re);
    }
    Ok(CompiledRules {
        flags: r.flags.clone(),
        value_flags,
        kind: r.positional.kind,
        min: r.positional.min,
        max: r.positional.max,
    })
}

fn next_value<'a>(
    args: &'a [String],
    i: &mut usize,
    ctx: &str,
    flag: &str,
) -> Result<&'a str, PolicyError> {
    let v = args.get(*i).ok_or_else(|| PolicyError::MissingValue {
        ctx: ctx.into(),
        flag: flag.into(),
    })?;
    *i += 1;
    Ok(v)
}

fn check_value(re: &Regex, ctx: &str, flag: &str, value: &str) -> Result<(), PolicyError> {
    if re.is_match(value) {
        Ok(())
    } else {
        Err(PolicyError::BadValue {
            ctx: ctx.into(),
            flag: flag.into(),
            value: value.into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse;

    struct Fixture {
        _dir: tempfile::TempDir,
        root: PathBuf,
        policy: Policy,
    }

    fn fixture() -> Fixture {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("logs")).unwrap();
        std::fs::write(root.join("logs/app.log"), "hello\n").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink("/etc", root.join("escape")).unwrap();

        let example = include_str!("../config/example.toml");
        let mut cfg = Config::from_toml(example).unwrap();
        cfg.server.workdir = root.clone();
        cfg.server.allowed_paths = vec![root.clone()];
        let policy = Policy::new(&cfg).unwrap();
        Fixture {
            _dir: dir,
            root,
            policy,
        }
    }

    impl Fixture {
        fn check(&self, cmd: &str) -> Result<Vec<Stage>, PolicyError> {
            self.policy.check(&parse(cmd).unwrap(), &self.root)
        }
        fn ok(&self, cmd: &str) {
            if let Err(e) = self.check(cmd) {
                panic!("expected {cmd:?} to be allowed: {e}");
            }
        }
        fn denied(&self, cmd: &str) -> PolicyError {
            match self.check(cmd) {
                Ok(_) => panic!("expected {cmd:?} to be denied"),
                Err(e) => e,
            }
        }
    }

    #[test]
    fn agents_md_examples_allowed() {
        let f = fixture();
        f.ok("ls -la");
        f.ok("pwd");
        f.ok("docker ps | grep postgres");
        f.ok("docker logs -f my-postgres_1");
        f.ok("docker images");
        f.ok("docker inspect abc123 def456");
        f.ok("docker events --since 10m");
        f.ok("docker history nginx:1.27");
    }

    #[test]
    fn flags_and_values() {
        let f = fixture();
        f.ok("ls -lah logs");
        f.ok("ls -l -a -- logs");
        f.ok("grep -nA3 hello logs/app.log");
        f.ok("grep -n -A 3 -i hello logs/app.log");
        f.ok("grep -e hello -r logs");
        f.ok("grep --regexp=hello logs");
        f.ok("docker ps -a --format '{{.Names}}' --filter status=running");
        f.ok("docker logs --tail=100 -t db");
        f.ok("docker logs -n 50 db");
        f.ok("docker ps | grep -v exited | grep -c db");
    }

    #[test]
    fn rejections() {
        let f = fixture();
        assert!(matches!(
            f.denied("rm -rf /"),
            PolicyError::UnknownCommand(_)
        ));
        assert!(matches!(
            f.denied("sh -c id"),
            PolicyError::UnknownCommand(_)
        ));
        assert!(matches!(
            f.denied("/bin/ls"),
            PolicyError::UnknownCommand(_)
        ));
        assert!(matches!(
            f.denied("docker"),
            PolicyError::MissingSubcommand { .. }
        ));
        assert!(matches!(
            f.denied("docker exec db sh"),
            PolicyError::UnknownSubcommand { .. }
        ));
        assert!(matches!(
            f.denied("docker run --privileged x"),
            PolicyError::UnknownSubcommand { .. }
        ));
        assert!(matches!(
            f.denied("docker -H tcp://x ps"),
            PolicyError::UnknownSubcommand { .. }
        ));
        assert!(matches!(f.denied("ls -L"), PolicyError::UnknownFlag { .. }));
        assert!(matches!(
            f.denied("ls -laL"),
            PolicyError::UnknownFlag { .. }
        ));
        assert!(matches!(
            f.denied("grep -f /etc/shadow x"),
            PolicyError::UnknownFlag { .. }
        ));
        assert!(matches!(
            f.denied("grep --file=/etc/shadow x"),
            PolicyError::UnknownFlag { .. }
        ));
        assert!(matches!(
            f.denied("ls --all=yes"),
            PolicyError::UnknownFlag { .. }
        ));
        assert!(matches!(
            f.denied("grep -A"),
            PolicyError::MissingValue { .. }
        ));
        assert!(matches!(
            f.denied("grep -A x y"),
            PolicyError::BadValue { .. }
        ));
        assert!(matches!(
            f.denied("grep -A3x y"),
            PolicyError::BadValue { .. }
        ));
        assert!(matches!(
            f.denied("docker logs --tail '1;id' db"),
            PolicyError::BadValue { .. }
        ));
        assert!(matches!(
            f.denied("docker ps --filter 'x=$(id)'"),
            PolicyError::BadValue { .. }
        ));
        assert!(matches!(
            f.denied("docker logs"),
            PolicyError::PositionalCount { .. }
        ));
        assert!(matches!(
            f.denied("docker logs a b"),
            PolicyError::PositionalCount { .. }
        ));
        assert!(matches!(
            f.denied("pwd extra"),
            PolicyError::PositionalCount { .. }
        ));
        assert!(matches!(
            f.denied("docker logs -- -rf"),
            PolicyError::BadContainer { .. }
        ));
        assert!(matches!(
            f.denied("docker logs ../../x"),
            PolicyError::BadContainer { .. }
        ));
    }

    #[test]
    fn system_commands() {
        let f = fixture();
        f.ok("cat logs/app.log");
        f.ok("cat -n logs/app.log | grep hello");
        f.ok("ls -l | cat");
        f.ok("awk '{print $1}' logs/app.log");
        f.ok("cat logs/app.log | awk -F: -v n=1 'NR > n {print $2}'");
        f.ok("top");
        f.ok("top -c -o %MEM -p 1,2");
        f.ok("dmesg -T --level err,warn | grep -i oom");
        f.ok("df -h");
        f.ok("df -hT --output=source,size logs");
        f.ok("free -h");
        f.ok("swapon --show");
        f.ok("swapon");

        // fixed_args are prepended and can't be removed by the client
        let st = f.check("awk '{print}' logs/app.log").unwrap();
        assert_eq!(st[0].args[0], "--sandbox");
        let st = f.check("top -c").unwrap();
        assert_eq!(st[0].args, ["-b", "-n", "1", "-c"]);

        let denied = [
            "cat /etc/shadow",
            "cat ../../etc/passwd",
            "awk",                          // program required
            "awk -f prog.awk logs/app.log", // program file
            "awk -e 'BEGIN{}' logs/app.log",
            "awk --source 'BEGIN{}'",
            "awk -l filefuncs 'BEGIN{}'",
            "awk '{print}' /etc/passwd", // file outside allowed paths
            "top -n 100",                // can't override batch iteration count
            "top -d 0.1",
            "dmesg -c", // clear ring buffer
            "dmesg -C",
            "dmesg -n 1", // console level
            "dmesg -D",
            "dmesg -F /etc/shadow",
            "dmesg --level all;id",
            "df /etc",
            "swapon -a", // enable all swap
            "swapon -e",
            "swapon /dev/sda2", // enable a device
            "swapon --show=NAME,SIZE",
            "free -s",
        ];
        for cmd in denied {
            if let Ok(pipeline) = parse(cmd) {
                assert!(
                    f.policy.check(&pipeline, &f.root).is_err(),
                    "expected {cmd:?} to be denied"
                );
            }
        }
    }

    #[test]
    fn diagnostic_commands() {
        let f = fixture();
        f.ok("journalctl -u nginx.service -n 100 --since '1 hour ago' -p err");
        f.ok("journalctl -fu sshd");
        f.ok("journalctl -b --boot=-1 -o json _PID=1");
        f.ok("journalctl -k | grep -i oom");
        f.ok("uptime");
        f.ok("uptime -p");
        f.ok("uname -a");
        f.ok("ps -ef");
        f.ok("ps -eo pid,%cpu,%mem,cmd --sort=-%mem | grep postgres");
        f.ok("ps -p 1,2 -o pid=");
        f.ok("vmstat 1 5");
        f.ok("vmstat -s -S M");
        f.ok("strace -p 1234");
        f.ok("strace -fttT -e trace=network -s 256 -p 1234");
        f.ok("strace -c -e openat,read -p 1,2");
        f.ok("du -sh logs");
        f.ok("du -h -d 1 --exclude '*.gz'");
        f.ok("lsblk");
        f.ok("lsblk -f -o NAME,SIZE,MOUNTPOINT");
        f.ok("ping -c 4 example.com");
        f.ok("ping -c3 -i 0.5 10.0.0.1");
        f.ok("ss -tlnp");
        f.ok("ss -tn state established '( dport = :443 )'");
        f.ok("ip a");
        f.ok("ip address");
        f.ok("ip route");
        f.ok("ip r");
        f.ok("nslookup example.com");
        f.ok("nslookup example.com 1.1.1.1");
        f.ok("host example.com");
        f.ok("host -t mx example.com 8.8.8.8");

        let st = f.check("journalctl -n 5").unwrap();
        assert_eq!(st[0].args, ["--no-pager", "-n", "5"]);

        let denied = [
            "journalctl --vacuum-size=1M",
            "journalctl --rotate",
            "journalctl --flush",
            "journalctl -D /tmp",
            "journalctl --file=/etc/shadow",
            "journalctl --cursor-file=/tmp/x",
            "journalctl -o export",
            "uname --version=x",
            "ps aux", // BSD style
            "ps e",
            "ps -o 'pid;id'",
            "strace ls", // must not launch programs
            "strace -- /bin/sh",
            "strace -o /tmp/x -p 1",
            "strace -o '|sh' -p 1",
            "strace -e inject=read:error=EIO -p 1",
            "strace -e fault=read -p 1",
            "strace -e read=3 -p 1",
            "strace --inject=read:error=EIO -p 1",
            "strace -E LD_PRELOAD=x -p 1",
            "strace -u root -p 1",
            "strace -p 'self'",
            "du /etc",
            "du -L logs",
            "du --files0-from=/etc/passwd",
            "lsblk /dev/sda",
            "ping -f 10.0.0.1",
            "ping -l 100 10.0.0.1",
            "ping -i 0.01 10.0.0.1",
            "ping -b 255.255.255.255",
            "ping",
            "ping a b",
            "ss -K dst 10.0.0.1",
            "ss -D /tmp/x",
            "ss -F /etc/shadow",
            "ss -N other",
            "ip",
            "ip link set eth0 down",
            "ip addr add 10.0.0.2/24 dev eth0",
            "ip addr flush dev eth0",
            "ip route add default via 10.0.0.1",
            "ip route del default",
            "ip -br a",
            "ip netns exec x sh",
            "nslookup",
            "host -l example.com",
            "host",
        ];
        for cmd in denied {
            if let Ok(pipeline) = parse(cmd) {
                assert!(
                    f.policy.check(&pipeline, &f.root).is_err(),
                    "expected {cmd:?} to be denied"
                );
            }
        }
    }

    #[test]
    fn path_confinement() {
        let f = fixture();
        f.ok("ls logs/app.log");
        f.ok("ls ./logs/../logs");
        f.ok("ls -");
        f.ok("grep /etc/passwd logs"); // first positional is the pattern, not a path
        assert!(matches!(
            f.denied("ls /etc"),
            PolicyError::PathDenied { .. }
        ));
        assert!(matches!(f.denied("ls .."), PolicyError::PathDenied { .. }));
        assert!(matches!(
            f.denied("ls logs/../.."),
            PolicyError::PathDenied { .. }
        ));
        assert!(matches!(
            f.denied("ls missing"),
            PolicyError::PathDenied { .. }
        ));
        assert!(matches!(
            f.denied("grep root /etc/passwd"),
            PolicyError::PathDenied { .. }
        ));
        assert!(matches!(
            f.denied("grep -e root /etc/passwd"),
            PolicyError::PathDenied { .. }
        ));
        assert!(matches!(
            f.denied("ls -- /etc"),
            PolicyError::PathDenied { .. }
        ));
        #[cfg(unix)]
        assert!(matches!(
            f.denied("ls escape/"),
            PolicyError::PathDenied { .. }
        ));
    }

    #[test]
    fn cwd_confinement() {
        let f = fixture();
        assert_eq!(
            f.policy.check_cwd(Path::new("logs"), &f.root).unwrap(),
            f.root.join("logs")
        );
        assert!(f.policy.check_cwd(Path::new("/"), &f.root).is_err());
        assert!(
            f.policy
                .check_cwd(Path::new("logs/app.log"), &f.root)
                .is_err()
        );
    }

    #[test]
    fn describe_lists_everything() {
        let f = fixture();
        let d = f.policy.describe();
        for needle in [
            "ls",
            "grep",
            "docker logs",
            "docker ps",
            "--tail",
            "container/image",
            "always runs with: --sandbox",
            "always runs with: -b -n 1",
        ] {
            assert!(d.contains(needle), "missing {needle} in:\n{d}");
        }
    }
}
