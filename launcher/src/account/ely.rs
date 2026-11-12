//! Ely.by OAuth device-code authentication. This module deliberately stops at OAuth tokens:
//! Minecraft profile lookup, account storage and the game-session bridge are separate steps.
//! The device code and bearer tokens are credentials: never include them in Debug, logs or errors.

use super::{now, request_to, send, str_field, Body};
use serde_json::Value;
use std::time::{Duration, Instant};

/// Public client ID registered for ElyRizon on Ely.by. This is an identifier, not a secret.
pub const DEFAULT_CLIENT_ID: &str = "elyrizon";

pub const SCOPES: &str = "account_info offline_access minecraft_server_session";

/// Public Ely.by endpoints. Fields are public so tests can point them at a local mock server.
#[derive(Clone, Debug)]
pub struct Endpoints {
    pub device_code: String,
    pub token: String,
    pub account_info: String,
    pub minecraft_profile: String,
}

impl Endpoints {
    pub fn live() -> Self {
        Self {
            device_code: "https://account.ely.by/api/oauth2/v1/devicecode".into(),
            token: "https://account.ely.by/api/oauth2/v1/token".into(),
            account_info: "https://account.ely.by/api/account/v1/info".into(),
            minecraft_profile: "https://account.ely.by/api/mojang/services/minecraft/profile"
                .into(),
        }
    }
}

/// Ely.by's public application identifier. It is not a secret; never embed a client secret in
/// the desktop binary. A run-time override is useful for developers testing another registration.
pub fn client_id() -> String {
    std::env::var("HORIZON_ELY_CLIENT_ID")
        .ok()
        .or_else(|| option_env!("HORIZON_ELY_CLIENT_ID").map(str::to_owned))
        .map(|id| id.trim().to_owned())
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| DEFAULT_CLIENT_ID.to_owned())
}

/// The code the player enters on Ely.by's official page. The private device_code is never shown.
#[derive(Clone, PartialEq)]
pub struct DeviceCode {
    pub user_code: String,
    pub verification_uri: String,
    pub interval: u64,
    pub expires_at: u64,
    device_code: String,
}

impl std::fmt::Debug for DeviceCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceCode")
            .field("user_code", &self.user_code)
            .field("verification_uri", &self.verification_uri)
            .field("interval", &self.interval)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

/// OAuth credentials. Debug intentionally hides both tokens.
#[derive(Clone)]
pub struct Tokens {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_at: u64,
}

impl std::fmt::Debug for Tokens {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ElyTokens(<hidden>)")
    }
}

pub enum Poll {
    Pending,
    SlowDown,
    Done(Tokens),
}

fn oauth_error(v: &Value) -> String {
    match v.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => "Ely.by is waiting for you to approve the sign-in.".into(),
        Some("slow_down") => "Ely.by asked the launcher to wait before checking again.".into(),
        Some("access_denied") | Some("authorization_declined") => {
            "Ely.by sign-in was declined.".into()
        }
        Some("expired_token") | Some("bad_verification_code") => {
            "The Ely.by sign-in code expired. Start again.".into()
        }
        Some("invalid_grant") => "The Ely.by sign-in expired. Sign in again.".into(),
        Some("invalid_client" | "unauthorized_client") => {
            "Ely.by refused this launcher's application ID.".into()
        }
        Some(other) => format!("Ely.by sign-in failed ({other})."),
        None => "Ely.by sign-in failed.".into(),
    }
}

pub fn device_code(ep: &Endpoints, client_id: &str) -> Result<DeviceCode, String> {
    let (status, v) = send(
        request_to("POST", &ep.device_code),
        Some(Body::Form(vec![("client_id", client_id), ("scope", SCOPES)])),
        "Ely.by",
    )?;

    let (Some(device_code), Some(user_code), Some(uri)) = (
        str_field(&v, "device_code"),
        str_field(&v, "user_code"),
        str_field(&v, "verification_uri"),
    ) else {
        return Err(oauth_error(&v));
    };
    if status != 200 {
        return Err(oauth_error(&v));
    }

    let expires_in = v
        .get("expires_in")
        .and_then(Value::as_u64)
        .filter(|seconds| *seconds > 0)
        .ok_or_else(|| "Ely.by returned an invalid sign-in expiry.".to_string())?
        .min(3600);

    Ok(DeviceCode {
        device_code,
        user_code,
        verification_uri: uri,
        interval: v
            .get("interval")
            .and_then(Value::as_u64)
            .unwrap_or(5)
            .clamp(1, 60),
        expires_at: now().saturating_add(expires_in),
    })
}

/// Poll once. The device_code is sent only to Ely.by's token endpoint.
pub fn poll(ep: &Endpoints, client_id: &str, code: &DeviceCode) -> Result<Poll, String> {
    let (status, v) = send(
        request_to("POST", &ep.token),
        Some(Body::Form(vec![
            ("client_id", client_id),
            (
                "grant_type",
                "urn:ietf:params:oauth:grant-type:device_code",
            ),
            ("device_code", &code.device_code),
        ])),
        "Ely.by",
    )?;

    match v.get("error").and_then(Value::as_str) {
        Some("authorization_pending") => return Ok(Poll::Pending),
        Some("slow_down") => return Ok(Poll::SlowDown),
        Some(_) => return Err(oauth_error(&v)),
        None => {}
    }

    let (Some(access_token), Some(refresh_token)) = (
        str_field(&v, "access_token"),
        str_field(&v, "refresh_token"),
    ) else {
        return Err(oauth_error(&v));
    };
    if status != 200 {
        return Err(oauth_error(&v));
    }
    let expires_in = v
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(3600)
        .min(7 * 86_400);

    Ok(Poll::Done(Tokens {
        access_token,
        refresh_token,
        expires_at: now().saturating_add(expires_in),
    }))
}

/// Wait for approval without blocking the UI thread. Call this from the launcher's account worker.
pub fn wait_for_sign_in(
    ep: &Endpoints,
    client_id: &str,
    code: &DeviceCode,
    cancelled: &dyn Fn() -> bool,
) -> Result<Tokens, String> {
    let mut interval = code.interval;
    loop {
        let until = Instant::now() + Duration::from_secs(interval);
        while Instant::now() < until {
            if cancelled() {
                return Err("Ely.by sign-in cancelled.".into());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        if cancelled() {
            return Err("Ely.by sign-in cancelled.".into());
        }
        if now() >= code.expires_at {
            return Err("The Ely.by sign-in code expired. Start again.".into());
        }
        match poll(ep, client_id, code)? {
            Poll::Pending => {}
            Poll::SlowDown => interval = (interval + 5).min(60),
            Poll::Done(tokens) => return Ok(tokens),
        }
    }
}

/// Refresh an Ely.by access token. A rotated refresh token is used when returned; otherwise the
/// existing one is retained. The scopes must be the same as those granted at sign-in.
pub fn refresh(
    ep: &Endpoints,
    client_id: &str,
    refresh_token: &str,
) -> Result<Tokens, String> {
    let (status, v) = send(
        request_to("POST", &ep.token),
        Some(Body::Form(vec![
            ("client_id", client_id),
            ("grant_type", "refresh_token"),
            ("refresh_token", refresh_token),
            ("scope", SCOPES),
        ])),
        "Ely.by",
    )?;
    let Some(access_token) = str_field(&v, "access_token").filter(|_| status == 200) else {
        return Err(oauth_error(&v));
    };
    let expires_in = v
        .get("expires_in")
        .and_then(Value::as_u64)
        .unwrap_or(3600)
        .min(7 * 86_400);
    Ok(Tokens {
        access_token,
        refresh_token: str_field(&v, "refresh_token").unwrap_or_else(|| refresh_token.into()),
        expires_at: now().saturating_add(expires_in),
    })
}
