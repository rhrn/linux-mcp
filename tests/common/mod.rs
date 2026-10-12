//! Shared test environment: temp dir, sample data, fake docker, config file.
#![allow(dead_code)]

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

pub struct TestEnv {
    pub dir: tempfile::TempDir,
    pub root: PathBuf,
    pub cfg: toml::Table,
}

impl TestEnv {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        std::fs::create_dir(root.join("data")).unwrap();
        std::fs::write(
            root.join("data/app.log"),
            "boot\npostgres ready\nshutdown\n",
        )
        .unwrap();

        // Fake docker: prints its arguments, and follows forever for `logs -f`.
        let fake = root.join("docker");
        std::fs::write(
            &fake,
            "#!/bin/sh\n\
             if [ \"$1\" = ps ]; then printf 'web nginx\\ndb postgres:16\\ncache redis\\n'; exit 0; fi\n\
             if [ \"$1 $2\" = 'logs -f' ]; then while :; do echo \"log line\"; sleep 0.1; done; fi\n\
             echo \"docker $*\"\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();

        let mut cfg: toml::Table =
            toml::from_str(include_str!("../../config/example.toml")).unwrap();
        let data = root.join("data").display().to_string();
        let server = cfg["server"].as_table_mut().unwrap();
        server.insert("workdir".into(), data.clone().into());
        server.insert(
            "allowed_paths".into(),
            toml::Value::Array(vec![data.into()]),
        );
        server.insert(
            "audit_log".into(),
            root.join("audit.jsonl").display().to_string().into(),
        );
        set_binary(&mut cfg, "docker", fake.display().to_string());
        for cmd in ["ls", "pwd", "grep"] {
            set_binary(&mut cfg, cmd, which(cmd));
        }
        Self { dir, root, cfg }
    }

    /// Write the (possibly modified) config and return its path.
    pub fn write_config(&self) -> PathBuf {
        let path = self.root.join("config.toml");
        std::fs::write(&path, toml::to_string(&self.cfg).unwrap()).unwrap();
        path
    }

    pub fn audit_lines(&self) -> Vec<serde_json::Value> {
        std::fs::read_to_string(self.root.join("audit.jsonl"))
            .unwrap_or_default()
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect()
    }
}

fn set_binary(cfg: &mut toml::Table, cmd: &str, path: String) {
    cfg["commands"][cmd]
        .as_table_mut()
        .unwrap()
        .insert("binary".into(), path.into());
}

fn which(cmd: &str) -> String {
    for dir in ["/bin", "/usr/bin"] {
        let p = Path::new(dir).join(cmd);
        if p.exists() {
            return p.display().to_string();
        }
    }
    panic!("{cmd} not found");
}
