//! Password-based authentication provider.

use async_trait::async_trait;
use gp_proto::prelogin::PreloginResponse;
use gp_proto::Credential;

use crate::context::AuthContext;
use crate::error::AuthError;
use crate::AuthProvider;

/// Authenticates with username + password (+ optional TOTP).
///
/// Uses pre-filled values from [`AuthContext`] when available, otherwise
/// prompts interactively via the terminal.
pub struct PasswordAuthProvider;

#[async_trait]
impl AuthProvider for PasswordAuthProvider {
    fn name(&self) -> &str {
        "password"
    }

    fn can_handle(&self, prelogin: &PreloginResponse) -> bool {
        matches!(prelogin, PreloginResponse::Standard(_))
    }

    async fn authenticate(
        &self,
        prelogin: &PreloginResponse,
        ctx: &AuthContext,
    ) -> Result<Credential, AuthError> {
        let standard = match prelogin {
            PreloginResponse::Standard(s) => s,
            _ => return Err(AuthError::Failed("not a password auth flow".into())),
        };

        let username = match ctx.username {
            Some(ref u) => u.clone(),
            None => dialoguer::Input::<String>::new()
                .with_prompt(&standard.label_username)
                .interact_text()
                .map_err(|e| AuthError::Failed(format!("prompt error: {e}")))?,
        };

        let password = match ctx.password {
            Some(ref p) => p.clone(),
            None => dialoguer::Password::new()
                .with_prompt(&standard.label_password)
                .interact()
                .map_err(|e| AuthError::Failed(format!("prompt error: {e}")))?,
        };

        Ok(Credential::Password { username, password })
    }
}
