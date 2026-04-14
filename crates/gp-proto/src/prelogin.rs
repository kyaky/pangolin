//! Prelogin response parsing.
//!
//! The prelogin endpoint (`prelogin.esp`) tells the client what authentication
//! method the portal or gateway expects (password vs SAML).

use crate::error::ProtoError;
use crate::xml::XmlNode;

/// Parsed prelogin response from a portal or gateway.
#[derive(Debug, Clone)]
pub enum PreloginResponse {
    /// Standard username + password authentication.
    Standard(StandardPrelogin),
    /// SAML-based authentication (browser redirect or POST).
    Saml(SamlPrelogin),
}

/// Fields for standard (password) authentication.
#[derive(Debug, Clone)]
pub struct StandardPrelogin {
    pub region: String,
    pub auth_message: String,
    pub label_username: String,
    pub label_password: String,
}

/// Fields for SAML authentication.
#[derive(Debug, Clone)]
pub struct SamlPrelogin {
    pub region: String,
    /// `"POST"` or `"REDIRECT"`.
    pub saml_auth_method: String,
    /// Base64-encoded SAML request body or redirect URL.
    pub saml_request: String,
}

impl PreloginResponse {
    /// Parse from the XML body returned by `prelogin.esp`.
    pub fn parse(xml: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;

        // Check status
        let status = root.child_text("status").unwrap_or("Success");
        if !status.eq_ignore_ascii_case("success") {
            return Err(ProtoError::UnexpectedStatus(status.to_string()));
        }

        let region = root.child_text("region").unwrap_or("Unknown").to_string();

        // SAML auth?
        if let Some(method) = root.child_text("saml-auth-method") {
            let request = root
                .child_text("saml-request")
                .ok_or(ProtoError::MissingField {
                    field: "saml-request",
                    context: "SAML prelogin response",
                })?
                .to_string();

            return Ok(Self::Saml(SamlPrelogin {
                region,
                saml_auth_method: method.to_string(),
                saml_request: request,
            }));
        }

        // Standard (password) auth
        Ok(Self::Standard(StandardPrelogin {
            region,
            auth_message: root
                .child_text("authentication-message")
                .unwrap_or("Enter login credentials")
                .to_string(),
            label_username: root
                .child_text("username-label")
                .unwrap_or("Username")
                .to_string(),
            label_password: root
                .child_text("password-label")
                .unwrap_or("Password")
                .to_string(),
        }))
    }

    /// Server region string.
    pub fn region(&self) -> &str {
        match self {
            Self::Standard(s) => &s.region,
            Self::Saml(s) => &s.region,
        }
    }

    /// Whether the server requires SAML authentication.
    pub fn is_saml(&self) -> bool {
        matches!(self, Self::Saml(_))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_standard() {
        let xml = r#"
        <prelogin-response>
            <status>Success</status>
            <region>Americas</region>
            <authentication-message>Sign in</authentication-message>
            <username-label>Email</username-label>
            <password-label>Secret</password-label>
        </prelogin-response>"#;

        let resp = PreloginResponse::parse(xml).unwrap();
        assert!(!resp.is_saml());
        assert_eq!(resp.region(), "Americas");

        if let PreloginResponse::Standard(s) = &resp {
            assert_eq!(s.auth_message, "Sign in");
            assert_eq!(s.label_username, "Email");
            assert_eq!(s.label_password, "Secret");
        } else {
            panic!("expected Standard");
        }
    }

    #[test]
    fn parse_saml() {
        let xml = r#"
        <prelogin-response>
            <status>Success</status>
            <region>EMEA</region>
            <saml-auth-method>REDIRECT</saml-auth-method>
            <saml-request>aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20=</saml-request>
        </prelogin-response>"#;

        let resp = PreloginResponse::parse(xml).unwrap();
        assert!(resp.is_saml());

        if let PreloginResponse::Saml(s) = &resp {
            assert_eq!(s.saml_auth_method, "REDIRECT");
            assert_eq!(s.saml_request, "aHR0cHM6Ly9pZHAuZXhhbXBsZS5jb20=");
        } else {
            panic!("expected Saml");
        }
    }

    #[test]
    fn parse_error_status() {
        let xml = r#"<prelogin-response><status>Error</status></prelogin-response>"#;
        assert!(PreloginResponse::parse(xml).is_err());
    }
}
