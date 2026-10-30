//! How the API builds its Bitcoin Core gateway from its settings.

use std::path::PathBuf;

use stealth_bitcoincore::{read_cookie_file, BitcoinCoreRpc, RpcAuth};
use stealth_engine::error::AnalysisError;

/// RPC settings the API reads from `STEALTH_RPC_*`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcSettings {
    pub url: String,
    pub user: Option<String>,
    pub pass: Option<String>,
    pub cookie: Option<PathBuf>,
}

/// Pick the auth: explicit user/pass, cookie path, bitcoin.conf, detected cookie, none.
pub fn select_auth(
    settings: &RpcSettings,
    bitcoin_conf: impl FnOnce() -> Option<(String, String)>,
    detect_cookie: impl FnOnce() -> Option<PathBuf>,
) -> RpcAuth {
    if let (Some(user), Some(pass)) = (&settings.user, &settings.pass) {
        return RpcAuth::UserPass(user.clone(), pass.clone());
    }
    if let Some(cookie) = &settings.cookie {
        return RpcAuth::CookieFile(cookie.clone());
    }
    if let Some((user, pass)) = bitcoin_conf() {
        return RpcAuth::UserPass(user, pass);
    }
    detect_cookie().map_or(RpcAuth::None, RpcAuth::CookieFile)
}

/// Build the gateway; a cookie is handed over as a path so the gateway re-reads it after a node restart.
pub fn build_gateway(
    settings: &RpcSettings,
    bitcoin_conf: impl FnOnce() -> Option<(String, String)>,
    detect_cookie: impl FnOnce() -> Option<PathBuf>,
) -> Result<BitcoinCoreRpc, AnalysisError> {
    let auth = select_auth(settings, bitcoin_conf, detect_cookie);
    // Fail at startup on an unreadable cookie, as before; the gateway reads its own copy.
    if let RpcAuth::CookieFile(path) = &auth {
        read_cookie_file(path)?;
    }
    let kind = match &auth {
        RpcAuth::UserPass(..) => "userpass",
        RpcAuth::CookieFile(_) => "cookie",
        RpcAuth::None => "none",
    };
    tracing::info!(rpc_url = %settings.url, rpc_auth = kind, "stealth-api RPC configured");
    BitcoinCoreRpc::from_url_auth(&settings.url, auth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> RpcSettings {
        RpcSettings {
            url: "http://127.0.0.1:18443".into(),
            ..RpcSettings::default()
        }
    }

    fn temp_cookie(name: &str) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("stealth-api-{}-{name}.cookie", std::process::id()));
        std::fs::write(&path, "__cookie__:secret").unwrap();
        path
    }

    fn no_conf() -> Option<(String, String)> {
        None
    }

    fn no_cookie() -> Option<PathBuf> {
        None
    }

    #[test]
    fn explicit_user_and_pass_win() {
        let cookie = temp_cookie("explicit");
        let settings = RpcSettings {
            user: Some("u".into()),
            pass: Some("p".into()),
            cookie: Some(cookie.clone()),
            ..settings()
        };
        let auth = select_auth(&settings, no_conf, || Some(cookie.clone()));
        std::fs::remove_file(&cookie).unwrap();
        assert_eq!(auth, RpcAuth::UserPass("u".into(), "p".into()));
    }

    #[test]
    fn a_given_cookie_is_handed_over_as_a_path() {
        let cookie = temp_cookie("given");
        let settings = RpcSettings {
            cookie: Some(cookie.clone()),
            ..settings()
        };
        let auth = select_auth(&settings, no_conf, no_cookie);
        std::fs::remove_file(&cookie).unwrap();
        assert_eq!(auth, RpcAuth::CookieFile(cookie));
    }

    #[test]
    fn a_detected_cookie_is_handed_over_as_a_path() {
        let cookie = temp_cookie("detected");
        let auth = select_auth(&settings(), no_conf, || Some(cookie.clone()));
        std::fs::remove_file(&cookie).unwrap();
        assert_eq!(auth, RpcAuth::CookieFile(cookie));
    }

    #[test]
    fn bitcoin_conf_credentials_come_before_a_detected_cookie() {
        let auth = select_auth(
            &settings(),
            || Some(("cu".into(), "cp".into())),
            || Some(PathBuf::from("/nowhere/.cookie")),
        );
        assert_eq!(auth, RpcAuth::UserPass("cu".into(), "cp".into()));
    }

    #[test]
    fn an_unreadable_cookie_fails_at_startup() {
        let settings = RpcSettings {
            cookie: Some(PathBuf::from("/nowhere/.cookie")),
            ..settings()
        };
        assert!(build_gateway(&settings, no_conf, no_cookie).is_err());
    }

    #[test]
    fn nothing_configured_means_no_auth() {
        assert_eq!(select_auth(&settings(), no_conf, no_cookie), RpcAuth::None);
    }
}
