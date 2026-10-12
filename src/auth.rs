//! Bearer-token authentication for the HTTP transport.
//!
//! The config stores only SHA-256 hashes of the tokens, so it can stay
//! world-readable; the plaintext token exists only on the client.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{HeaderValue, StatusCode, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use sha2::{Digest, Sha256};

use crate::audit::Caller;
use crate::config::{ConfigError, HttpKey};

const TOKEN_PREFIX: &str = "lmcp_";

/// Generate a new random token. Returns (token, sha256 hex of token).
pub fn generate_key() -> (String, String) {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).expect("OS random number generator unavailable");
    let token = format!("{TOKEN_PREFIX}{}", hex::encode(bytes));
    let hash = hex::encode(Sha256::digest(token.as_bytes()));
    (token, hash)
}

pub struct KeyStore {
    keys: Vec<(String, [u8; 32])>,
}

impl KeyStore {
    pub fn new(keys: &[HttpKey]) -> Result<Self, ConfigError> {
        if keys.is_empty() {
            return Err(ConfigError::Invalid(
                "http.keys is empty: generate one with `linux-mcp --gen-key <id>`".into(),
            ));
        }
        let mut out = Vec::with_capacity(keys.len());
        for k in keys {
            let mut hash = [0u8; 32];
            hex::decode_to_slice(&k.sha256, &mut hash).map_err(|_| {
                ConfigError::Invalid(format!(
                    "http.keys '{}': sha256 must be 64 hex characters",
                    k.id
                ))
            })?;
            if out.iter().any(|(id, _)| id == &k.id) {
                return Err(ConfigError::Invalid(format!(
                    "http.keys: duplicate id '{}'",
                    k.id
                )));
            }
            out.push((k.id.clone(), hash));
        }
        Ok(Self { keys: out })
    }

    /// Returns the key id if the token matches. Compares against every key in
    /// constant time so timing reveals nothing about which (if any) matched.
    pub fn verify(&self, token: &str) -> Option<&str> {
        let digest: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let mut found = None;
        for (id, hash) in &self.keys {
            if ct_eq(&digest, hash) {
                found = Some(id.as_str());
            }
        }
        found
    }
}

fn ct_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let diff = a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y));
    std::hint::black_box(diff) == 0
}

/// axum middleware: require `Authorization: Bearer <token>`, attach a [`Caller`].
pub async fn require_bearer(
    State(keys): State<Arc<KeyStore>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    mut req: Request,
    next: Next,
) -> Response {
    let token = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| {
            v.strip_prefix("Bearer ")
                .or_else(|| v.strip_prefix("bearer "))
        })
        .map(str::trim);

    match token.and_then(|t| keys.verify(t)) {
        Some(id) => {
            req.extensions_mut().insert(Caller {
                client_id: Some(id.to_owned()),
                remote: Some(remote.to_string()),
            });
            next.run(req).await
        }
        None => {
            tracing::warn!(%remote, presented = token.is_some(), "HTTP authentication failed");
            let mut resp = (StatusCode::UNAUTHORIZED, "unauthorized\n").into_response();
            resp.headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
            resp
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(id: &str, sha256: &str) -> HttpKey {
        HttpKey {
            id: id.into(),
            sha256: sha256.into(),
        }
    }

    #[test]
    fn generated_keys_verify() {
        let (t1, h1) = generate_key();
        let (t2, h2) = generate_key();
        assert!(t1.starts_with(TOKEN_PREFIX) && t1.len() == TOKEN_PREFIX.len() + 64);
        assert_ne!(t1, t2);
        let store = KeyStore::new(&[key("alice", &h1), key("bob", &h2)]).unwrap();
        assert_eq!(store.verify(&t1), Some("alice"));
        assert_eq!(store.verify(&t2), Some("bob"));
        assert_eq!(store.verify(""), None);
        assert_eq!(store.verify(&h1), None); // the hash itself is not a credential
        assert_eq!(store.verify(&t1[..t1.len() - 1]), None);
    }

    #[test]
    fn rejects_bad_config() {
        assert!(KeyStore::new(&[]).is_err());
        assert!(KeyStore::new(&[key("a", "zz")]).is_err());
        let (_, h) = generate_key();
        assert!(KeyStore::new(&[key("a", &h), key("a", &h)]).is_err());
    }
}
