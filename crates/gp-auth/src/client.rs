//! HTTP client for GlobalProtect API endpoints.

use gp_proto::*;

use crate::error::AuthError;

/// HTTP client wrapping the GlobalProtect REST-ish API.
pub struct GpClient {
    http: reqwest::Client,
    /// The GP request parameters attached to every call.
    pub gp_params: GpParams,
}

impl GpClient {
    /// Create a new client from the given parameters.
    pub fn new(gp_params: GpParams) -> Result<Self, AuthError> {
        let http = reqwest::Client::builder()
            .user_agent(&gp_params.user_agent)
            .danger_accept_invalid_certs(gp_params.ignore_tls_errors)
            .build()?;
        Ok(Self { http, gp_params })
    }

    /// Portal or gateway prelogin — determines the required auth method.
    pub async fn prelogin(&self, server: &str) -> Result<PreloginResponse, AuthError> {
        let url = self.gp_params.prelogin_url(server);
        let params = self.gp_params.to_prelogin_params();

        tracing::debug!("prelogin POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tracing::trace!("prelogin response ({} bytes)", body.len());
        Ok(PreloginResponse::parse(&body)?)
    }

    /// Retrieve the portal configuration (gateway list + auth cookies).
    ///
    /// This doubles as the "portal login" step — the credential is verified
    /// by the portal before it returns the config.
    pub async fn portal_config(
        &self,
        portal: &str,
        cred: &Credential,
    ) -> Result<PortalConfig, AuthError> {
        let url = self.gp_params.login_url(portal);
        let mut params = self.gp_params.to_params();
        params.extend(cred.to_params());
        let host = gp_proto::params::normalize_server(portal).to_string();
        params.push(("server", host.clone()));
        params.push(("host", host));

        tracing::debug!("portal config POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tracing::trace!("portal config response ({} bytes)", body.len());
        Ok(PortalConfig::parse(&body, portal, cred.username())?)
    }

    /// Gateway login — exchange credentials for an authcookie.
    pub async fn gateway_login(
        &self,
        gateway: &str,
        cred: &Credential,
    ) -> Result<GatewayLoginResult, AuthError> {
        let host = gp_proto::params::normalize_server(gateway);
        let url = format!("https://{host}/ssl-vpn/login.esp");
        let mut params = self.gp_params.to_params();
        params.extend(cred.to_params());
        params.push(("server", host.to_string()));

        tracing::debug!("gateway login POST {url}");
        let body = self
            .http
            .post(&url)
            .form(&params)
            .send()
            .await?
            .error_for_status()?
            .text()
            .await?;

        tracing::trace!("gateway login response ({} bytes)", body.len());
        Ok(GatewayLoginResult::parse(&body, &self.gp_params.computer)?)
    }
}
