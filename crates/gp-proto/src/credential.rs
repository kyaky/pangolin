//! Credential types used throughout the GP authentication flow.

/// Authentication credentials for GP API requests.
#[derive(Clone)]
pub enum Credential {
    /// Username + password for standard auth.
    Password { username: String, password: String },
    /// SAML result: either a classic `prelogin-cookie` or a Prisma Access
    /// `token` (the JWT pulled out of a `globalprotectcallback:` URI).
    /// Both fields are optional — exactly one will be populated depending
    /// on the portal type.
    Prelogin {
        username: String,
        prelogin_cookie: Option<String>,
        token: Option<String>,
    },
    /// Portal auth cookies for gateway login.
    AuthCookie {
        username: String,
        user_auth_cookie: String,
        prelogon_user_auth_cookie: String,
    },
}

impl Credential {
    /// The authenticated username.
    pub fn username(&self) -> &str {
        match self {
            Self::Password { username, .. } => username,
            Self::Prelogin { username, .. } => username,
            Self::AuthCookie { username, .. } => username,
        }
    }

    /// Convert to form parameters for API requests.
    ///
    /// GP portals always expect the full set of credential fields; missing
    /// ones must be sent as empty strings, so we emit them all and let the
    /// specific variant fill in the non-empty values (matches yuezk's
    /// `Credential::to_params`).
    pub fn to_params(&self) -> Vec<(&'static str, String)> {
        // Always emit every known credential key (with empty defaults)
        // so portal/gateway endpoints that validate field presence don't
        // diverge between credential variants. The `token` field is
        // included up front for Prisma Access — older portals ignore
        // it, newer ones require it.
        let mut params: Vec<(&'static str, String)> = vec![
            ("user", self.username().to_string()),
            ("passwd", String::new()),
            ("prelogin-cookie", String::new()),
            ("portal-userauthcookie", String::new()),
            ("portal-prelogonuserauthcookie", String::new()),
            ("token", String::new()),
        ];
        let set = |params: &mut Vec<(&'static str, String)>, key: &'static str, value: String| {
            if let Some(p) = params.iter_mut().find(|(k, _)| *k == key) {
                p.1 = value;
            } else {
                params.push((key, value));
            }
        };

        match self {
            Self::Password { password, .. } => {
                set(&mut params, "passwd", password.clone());
            }
            Self::Prelogin {
                prelogin_cookie,
                token,
                ..
            } => {
                if let Some(pc) = prelogin_cookie {
                    set(&mut params, "prelogin-cookie", pc.clone());
                }
                if let Some(tok) = token {
                    set(&mut params, "token", tok.clone());
                }
            }
            Self::AuthCookie {
                user_auth_cookie,
                prelogon_user_auth_cookie,
                ..
            } => {
                set(
                    &mut params,
                    "portal-userauthcookie",
                    user_auth_cookie.clone(),
                );
                set(
                    &mut params,
                    "portal-prelogonuserauthcookie",
                    prelogon_user_auth_cookie.clone(),
                );
            }
        }
        params
    }
}

/// The authcookie obtained from gateway login, used to establish the VPN tunnel.
#[derive(Clone)]
pub struct AuthCookie {
    pub username: String,
    pub authcookie: String,
    pub portal: String,
    pub domain: Option<String>,
    pub preferred_ip: Option<String>,
    pub computer: Option<String>,
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Password { username, .. } => f
                .debug_struct("Password")
                .field("username", username)
                .field("password", &"[REDACTED]")
                .finish(),
            Self::Prelogin {
                username,
                prelogin_cookie,
                token,
            } => f
                .debug_struct("Prelogin")
                .field("username", username)
                .field(
                    "prelogin_cookie",
                    &prelogin_cookie.as_ref().map(|_| "[REDACTED]"),
                )
                .field("token", &token.as_ref().map(|_| "[REDACTED]"))
                .finish(),
            Self::AuthCookie { username, .. } => f
                .debug_struct("AuthCookie")
                .field("username", username)
                .field("user_auth_cookie", &"[REDACTED]")
                .field("prelogon_user_auth_cookie", &"[REDACTED]")
                .finish(),
        }
    }
}

impl std::fmt::Debug for AuthCookie {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthCookie")
            .field("username", &self.username)
            .field("authcookie", &"[REDACTED]")
            .field("portal", &self.portal)
            .field("domain", &self.domain)
            .field("preferred_ip", &self.preferred_ip)
            .field("computer", &self.computer)
            .finish()
    }
}
