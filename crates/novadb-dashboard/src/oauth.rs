//! Discord / GitHub OAuth2 with `state` + PKCE (S256) + exact redirect URI (PLAN.md §4.9).
//! Accounts are linked only by a logged-in user; login looks up the provider user **id**.
//! There is no auto-create and no e-mail matching.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::Deserialize;

use crate::auth;

/// Pending flows expire after this long.
pub const FLOW_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Discord,
    Github,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Kind> {
        match s {
            "discord" => Some(Kind::Discord),
            "github" => Some(Kind::Github),
            _ => None,
        }
    }
    pub fn id(self) -> &'static str {
        match self {
            Kind::Discord => "discord",
            Kind::Github => "github",
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Kind::Discord => "Discord",
            Kind::Github => "GitHub",
        }
    }
    fn authorize_url(self) -> &'static str {
        match self {
            Kind::Discord => "https://discord.com/oauth2/authorize",
            Kind::Github => "https://github.com/login/oauth/authorize",
        }
    }
    fn token_url(self) -> &'static str {
        match self {
            Kind::Discord => "https://discord.com/api/oauth2/token",
            Kind::Github => "https://github.com/login/oauth/access_token",
        }
    }
    fn user_url(self) -> &'static str {
        match self {
            Kind::Discord => "https://discord.com/api/users/@me",
            Kind::Github => "https://api.github.com/user",
        }
    }
    fn scope(self) -> &'static str {
        match self {
            Kind::Discord => "identify",
            Kind::Github => "read:user",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Provider {
    pub kind: Kind,
    pub client_id: String,
    pub client_secret: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    Login,
    Link,
}

#[derive(Debug)]
pub struct Pending {
    pub kind: Kind,
    pub mode: Mode,
    pub verifier: String,
    /// Value of the browser-binding cookie that must come back with the callback.
    pub bind: String,
    /// Session key for link flows.
    pub session_key: Option<String>,
    pub created: Instant,
}

pub struct Flows {
    map: Mutex<HashMap<String, Pending>>,
}

impl Flows {
    pub fn new() -> Self {
        Flows {
            map: Mutex::new(HashMap::new()),
        }
    }

    /// Store a flow; returns (state, verifier challenge, bind cookie value).
    pub fn start(
        &self,
        kind: Kind,
        mode: Mode,
        session_key: Option<String>,
    ) -> Result<(String, String, String), String> {
        let state = auth::token()?;
        let verifier = auth::token()?;
        let bind = auth::token()?;
        let challenge = auth::pkce_challenge(&verifier);
        let mut m = self.map.lock().map_err(|_| "lock".to_string())?;
        m.retain(|_, p| p.created.elapsed() < FLOW_TTL);
        if m.len() >= MAX_PENDING {
            return Err("too many sign-in attempts in progress, try again shortly".into());
        }
        m.insert(
            state.clone(),
            Pending {
                kind,
                mode,
                verifier,
                bind: bind.clone(),
                session_key,
                created: Instant::now(),
            },
        );
        Ok((state, challenge, bind))
    }

    /// Single-use: removes the flow whatever the outcome.
    pub fn take(&self, state: &str) -> Option<Pending> {
        let mut m = self.map.lock().ok()?;
        let p = m.remove(state)?;
        (p.created.elapsed() < FLOW_TTL).then_some(p)
    }
}

fn pct(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            o.push(char::from(b));
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

pub fn authorize_url(p: &Provider, redirect_uri: &str, state: &str, challenge: &str) -> String {
    format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256&prompt=consent",
        p.kind.authorize_url(),
        pct(&p.client_id),
        pct(redirect_uri),
        pct(p.kind.scope()),
        pct(state),
        pct(challenge)
    )
}

#[derive(Deserialize)]
struct TokenResp {
    access_token: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
}

#[derive(Deserialize)]
struct GithubUser {
    id: u64,
    login: String,
}

/// Exchange the code and fetch the provider user. Returns (provider user id, display name).
pub async fn finish(
    http: &reqwest::Client,
    p: &Provider,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
) -> Result<(String, String), String> {
    let form = [
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri),
        ("client_id", p.client_id.as_str()),
        ("client_secret", p.client_secret.as_str()),
        ("code_verifier", verifier),
    ];
    let t: TokenResp = http
        .post(p.kind.token_url())
        .header("Accept", "application/json")
        .form(&form)
        .send()
        .await
        .map_err(|e| format!("token request failed: {e}"))?
        .json()
        .await
        .map_err(|e| format!("token response unreadable: {e}"))?;
    let Some(tok) = t.access_token else {
        return Err(format!(
            "provider refused the sign-in ({})",
            t.error.unwrap_or_else(|| "no token".into())
        ));
    };
    let req = http
        .get(p.kind.user_url())
        .bearer_auth(&tok)
        .header("Accept", "application/json");
    let resp = req
        .send()
        .await
        .map_err(|e| format!("user request failed: {e}"))?;
    if !resp.status().is_success() {
        return Err(format!("provider user lookup failed ({})", resp.status()));
    }
    match p.kind {
        Kind::Discord => {
            let u: DiscordUser = resp.json().await.map_err(|e| e.to_string())?;
            if u.id.is_empty() || !u.id.bytes().all(|b| b.is_ascii_digit()) {
                return Err("provider returned an invalid user id".into());
            }
            Ok((u.id, u.username))
        }
        Kind::Github => {
            let u: GithubUser = resp.json().await.map_err(|e| e.to_string())?;
            Ok((u.id.to_string(), u.login))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn flows_single_use() {
        let f = Flows::new();
        let (state, ch, bind) = f.start(Kind::Discord, Mode::Login, None).unwrap();
        assert_ne!(state, bind);
        let p = f.take(&state).unwrap();
        assert_eq!(auth::pkce_challenge(&p.verifier), ch);
        assert_eq!(p.bind, bind);
        assert!(f.take(&state).is_none(), "state must be single-use");
        assert!(f.take("unknown").is_none());
    }

    #[test]
    fn url_is_encoded() {
        let p = Provider {
            kind: Kind::Github,
            client_id: "id&x".into(),
            client_secret: "s".into(),
        };
        let u = authorize_url(&p, "https://h/cb?a=b", "st", "ch");
        assert!(u.contains("client_id=id%26x"));
        assert!(u.contains("redirect_uri=https%3A%2F%2Fh%2Fcb%3Fa%3Db"));
        assert!(u.contains("code_challenge_method=S256"));
    }
}
