//! Configuration file model (TOML) and loading.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read config {path}: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("invalid config {path}: {source}")]
    Parse {
        path: PathBuf,
        source: toml::de::Error,
    },
    #[error("insecure config {path}: {reason} (use --allow-insecure-config to override)")]
    Insecure { path: PathBuf, reason: String },
    #[error("invalid config: {0}")]
    Invalid(String),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub server: ServerSettings,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandSpec>,
    /// Settings for the HTTP transport (`--http`).
    #[serde(default)]
    pub http: Option<HttpSettings>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSettings {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Accepted bearer tokens, stored as SHA-256 hashes.
    #[serde(default)]
    pub keys: Vec<HttpKey>,
    /// PEM certificate chain and private key. When set, the server speaks HTTPS.
    pub tls_cert: Option<PathBuf>,
    pub tls_key: Option<PathBuf>,
    /// Allow plain HTTP on a non-loopback address (e.g. behind a TLS-terminating proxy).
    #[serde(default)]
    pub allow_plaintext: bool,
    /// Accepted `Host` header values (DNS-rebinding protection). Defaults to loopback
    /// names when listening on loopback; when listening elsewhere and unset, not checked.
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpKey {
    /// Client identifier, recorded in the audit log.
    pub id: String,
    /// Hex SHA-256 of the token (from `linux-mcp --gen-key`).
    pub sha256: String,
}

fn default_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8765))
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ServerSettings {
    /// Default working directory for commands.
    pub workdir: PathBuf,
    /// Path arguments (and `cwd`) must resolve inside one of these. Defaults to `[workdir]`.
    pub allowed_paths: Vec<PathBuf>,
    /// Cap on captured stdout and stderr (each) for a single `run`.
    pub max_output_bytes: usize,
    pub default_timeout_s: u64,
    pub max_timeout_s: u64,
    /// Maximum number of pipelines running at once (including streams).
    pub max_concurrent: usize,
    pub max_streams: usize,
    /// Upper bound for `stream_start` duration.
    pub max_stream_duration_s: u64,
    /// Streams not read for this long are killed.
    pub stream_idle_ttl_s: u64,
    /// `PATH` given to spawned processes.
    pub path_env: String,
    /// Extra environment variables for spawned processes (e.g. `DOCKER_HOST`).
    pub env: BTreeMap<String, String>,
    /// JSONL audit log. When unset, audit records go to the tracing log (stderr).
    pub audit_log: Option<PathBuf>,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            workdir: PathBuf::from("/"),
            allowed_paths: Vec::new(),
            max_output_bytes: 1024 * 1024,
            default_timeout_s: 30,
            max_timeout_s: 300,
            max_concurrent: 8,
            max_streams: 4,
            max_stream_duration_s: 3600,
            stream_idle_ttl_s: 300,
            path_env: "/usr/local/bin:/usr/bin:/bin".into(),
            env: BTreeMap::new(),
            audit_log: None,
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    /// Absolute path of the executable.
    pub binary: PathBuf,
    #[serde(default)]
    pub description: Option<String>,
    /// Arguments always inserted right after the binary, before the client's
    /// arguments (e.g. `--sandbox` for gawk, `-b -n 1` for top). Not validated.
    #[serde(default)]
    pub fixed_args: Vec<String>,
    /// Rules for arguments when the command has no subcommands.
    #[serde(flatten)]
    pub rules: ArgRules,
    /// When non-empty, the first argument must be one of these subcommands,
    /// and its arguments are checked by the subcommand's rules.
    #[serde(default)]
    pub subcommands: BTreeMap<String, ArgRules>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct ArgRules {
    /// Boolean flags, e.g. `-l`, `--all`.
    pub flags: Vec<String>,
    /// Flags taking a value, mapped to a regex the value must fully match.
    pub value_flags: BTreeMap<String, String>,
    pub positional: Positional,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Positional {
    pub kind: PositionalKind,
    #[serde(default)]
    pub min: usize,
    #[serde(default = "default_max_positional")]
    pub max: usize,
}

fn default_max_positional() -> usize {
    16
}

impl Default for Positional {
    fn default() -> Self {
        Self {
            kind: PositionalKind::Any,
            min: 0,
            max: 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PositionalKind {
    /// Filesystem paths, confined to `allowed_paths`.
    Path,
    /// First positional is a pattern, the rest are paths (grep). When the
    /// pattern is given via `-e`/`--regexp`, all positionals are paths.
    PatternThenPaths,
    /// Docker container / image name, ID or reference.
    Container,
    /// Anything (no shell is involved, but use with care).
    Any,
}

impl Config {
    pub fn load(path: &Path, allow_insecure: bool) -> Result<Self, ConfigError> {
        if !allow_insecure {
            check_permissions(path)?;
        }
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml(&text).map_err(|e| match e {
            ConfigError::Parse { source, .. } => ConfigError::Parse {
                path: path.to_owned(),
                source,
            },
            other => other,
        })
    }

    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let mut cfg: Config = toml::from_str(text).map_err(|source| ConfigError::Parse {
            path: PathBuf::new(),
            source,
        })?;
        if cfg.server.allowed_paths.is_empty() {
            cfg.server.allowed_paths = vec![cfg.server.workdir.clone()];
        }
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let s = &self.server;
        if !s.workdir.is_absolute() {
            return Err(ConfigError::Invalid(
                "server.workdir must be absolute".into(),
            ));
        }
        if s.default_timeout_s == 0 || s.default_timeout_s > s.max_timeout_s {
            return Err(ConfigError::Invalid(
                "server.default_timeout_s must be in 1..=max_timeout_s".into(),
            ));
        }
        if s.max_concurrent == 0 || s.max_output_bytes == 0 {
            return Err(ConfigError::Invalid(
                "server.max_concurrent and server.max_output_bytes must be > 0".into(),
            ));
        }
        for p in &s.allowed_paths {
            if !p.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "allowed path {} must be absolute",
                    p.display()
                )));
            }
        }
        if let Some(h) = &self.http {
            if h.tls_cert.is_some() != h.tls_key.is_some() {
                return Err(ConfigError::Invalid(
                    "http.tls_cert and http.tls_key must be set together".into(),
                ));
            }
            if h.tls_cert.is_none() && !h.listen.ip().is_loopback() && !h.allow_plaintext {
                return Err(ConfigError::Invalid(format!(
                    "http.listen {} is not loopback: configure tls_cert/tls_key, or set \
                     allow_plaintext = true if a TLS proxy sits in front",
                    h.listen
                )));
            }
        }
        for (name, spec) in &self.commands {
            if !spec.binary.is_absolute() {
                return Err(ConfigError::Invalid(format!(
                    "commands.{name}.binary must be an absolute path"
                )));
            }
            if !spec.subcommands.is_empty() && !rules_empty(&spec.rules) {
                return Err(ConfigError::Invalid(format!(
                    "commands.{name}: use either top-level rules or subcommands, not both"
                )));
            }
            let all_rules = std::iter::once((String::new(), &spec.rules))
                .chain(spec.subcommands.iter().map(|(k, v)| (format!(".{k}"), v)));
            for (sub, rules) in all_rules {
                for f in rules.flags.iter().chain(rules.value_flags.keys()) {
                    if !is_valid_flag_name(f) {
                        return Err(ConfigError::Invalid(format!(
                            "commands.{name}{sub}: invalid flag name {f:?}"
                        )));
                    }
                }
                if rules.positional.min > rules.positional.max {
                    return Err(ConfigError::Invalid(format!(
                        "commands.{name}{sub}: positional.min > positional.max"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn rules_empty(r: &ArgRules) -> bool {
    r.flags.is_empty() && r.value_flags.is_empty() && r.positional.max == 0
}

/// `-x` (single char) or `--long-name`.
fn is_valid_flag_name(f: &str) -> bool {
    let b = f.as_bytes();
    match b {
        [b'-', c] => c.is_ascii_alphanumeric(),
        [b'-', b'-', rest @ ..] if !rest.is_empty() => {
            rest.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
        }
        _ => false,
    }
}

#[cfg(unix)]
fn check_permissions(path: &Path) -> Result<(), ConfigError> {
    use std::os::unix::fs::MetadataExt;
    let insecure = |reason: String| ConfigError::Insecure {
        path: path.to_owned(),
        reason,
    };
    let meta = std::fs::metadata(path).map_err(|source| ConfigError::Read {
        path: path.to_owned(),
        source,
    })?;
    if meta.mode() & 0o022 != 0 {
        return Err(insecure("file is group- or world-writable".into()));
    }
    // SAFETY: geteuid has no preconditions.
    let euid = unsafe { libc::geteuid() };
    if euid != 0 && meta.uid() == euid {
        return Err(insecure(
            "file is owned by the user running the server; it should be owned by root".into(),
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_permissions(_path: &Path) -> Result<(), ConfigError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_example_config() {
        let text = include_str!("../config/example.toml");
        let cfg = Config::from_toml(text).unwrap();
        assert!(cfg.commands.contains_key("docker"));
        assert!(cfg.commands["docker"].subcommands.contains_key("logs"));
    }

    #[test]
    fn rejects_relative_binary() {
        let err = Config::from_toml("[commands.ls]\nbinary = \"ls\"\n").unwrap_err();
        assert!(err.to_string().contains("absolute"));
    }

    #[test]
    fn rejects_bad_flag_name() {
        let err = Config::from_toml("[commands.ls]\nbinary = \"/bin/ls\"\nflags = [\"-la\"]\n")
            .unwrap_err();
        assert!(err.to_string().contains("invalid flag"));
    }

    #[test]
    fn rejects_unknown_keys() {
        assert!(Config::from_toml("[server]\nbogus = 1\n").is_err());
    }

    #[test]
    fn http_plaintext_guard() {
        assert!(Config::from_toml("[http]\nlisten = \"127.0.0.1:9000\"\n").is_ok());
        let err = Config::from_toml("[http]\nlisten = \"0.0.0.0:9000\"\n").unwrap_err();
        assert!(err.to_string().contains("not loopback"));
        assert!(
            Config::from_toml("[http]\nlisten = \"0.0.0.0:9000\"\nallow_plaintext = true\n")
                .is_ok()
        );
        assert!(Config::from_toml("[http]\ntls_cert = \"/c.pem\"\n").is_err());
    }

    #[test]
    fn allowed_paths_default_to_workdir() {
        let cfg = Config::from_toml("[server]\nworkdir = \"/srv\"\n").unwrap();
        assert_eq!(cfg.server.allowed_paths, vec![PathBuf::from("/srv")]);
    }
}
