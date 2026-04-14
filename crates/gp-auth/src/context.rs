//! Shared authentication context.

/// Context passed to [`AuthProvider::authenticate`](crate::AuthProvider::authenticate).
#[derive(Clone)]
pub struct AuthContext {
    /// Portal or gateway hostname.
    pub server: String,
    /// Pre-filled username (from config or `--user` flag).
    pub username: Option<String>,
    /// Pre-filled password (from `--passwd-on-stdin`).
    pub password: Option<String>,
    /// Maximum MFA retry attempts.
    pub max_mfa_attempts: u32,
}

impl std::fmt::Debug for AuthContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthContext")
            .field("server", &self.server)
            .field("username", &self.username)
            .field("password", &self.password.as_ref().map(|_| "[REDACTED]"))
            .field("max_mfa_attempts", &self.max_mfa_attempts)
            .finish()
    }
}
