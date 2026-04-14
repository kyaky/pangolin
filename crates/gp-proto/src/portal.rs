//! Portal configuration response parsing.

use crate::credential::Credential;
use crate::error::ProtoError;
use crate::gateway::Gateway;
use crate::xml::XmlNode;

/// Configuration returned by the portal after authentication.
///
/// Parsed from the `/global-protect/getconfig.esp` response.
#[derive(Debug, Clone)]
pub struct PortalConfig {
    /// Portal hostname.
    pub portal: String,
    /// Authenticated username.
    pub username: String,
    /// Portal user-auth cookie.
    pub user_auth_cookie: String,
    /// Portal prelogon user-auth cookie.
    pub prelogon_user_auth_cookie: String,
    /// Available VPN gateways.
    pub gateways: Vec<Gateway>,
    /// Configuration digest (opaque hash).
    pub config_digest: Option<String>,
}

impl PortalConfig {
    /// Parse from the XML body of `/global-protect/getconfig.esp`.
    pub fn parse(xml: &str, portal: &str, username: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;

        // Use recursive search — real responses may nest these under
        // intermediate elements (e.g. <policy>).
        let user_auth_cookie = root
            .find_text("portal-userauthcookie")
            .unwrap_or("")
            .to_string();
        let prelogon_user_auth_cookie = root
            .find_text("portal-prelogonuserauthcookie")
            .unwrap_or("")
            .to_string();
        let config_digest = root.find_text("config-digest").map(|s| s.to_string());

        let mut gateways = root
            .find("gateways")
            .map(Gateway::parse_list)
            .unwrap_or_default();

        // Fallback: use the portal itself as a gateway.
        if gateways.is_empty() {
            gateways.push(Gateway {
                address: portal.to_string(),
                description: format!("{portal} (fallback)"),
                priority: 0,
                priority_rules: Vec::new(),
            });
        }

        Ok(Self {
            portal: portal.to_string(),
            username: username.to_string(),
            user_auth_cookie,
            prelogon_user_auth_cookie,
            gateways,
            config_digest,
        })
    }

    /// Build a [`Credential::AuthCookie`] for gateway login.
    pub fn to_gateway_credential(&self) -> Credential {
        Credential::AuthCookie {
            username: self.username.clone(),
            user_auth_cookie: self.user_auth_cookie.clone(),
            prelogon_user_auth_cookie: self.prelogon_user_auth_cookie.clone(),
        }
    }

    /// Select the best gateway, preferring the given region.
    pub fn preferred_gateway(&self, region: Option<&str>) -> Option<&Gateway> {
        if self.gateways.is_empty() {
            return None;
        }
        if let Some(region) = region {
            let mut sorted: Vec<_> = self.gateways.iter().collect();
            sorted.sort_by_key(|g| g.priority_for_region(region));
            Some(sorted[0])
        } else {
            self.gateways.iter().min_by_key(|g| g.priority)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_portal_config() {
        let xml = r#"
        <response>
            <portal-userauthcookie>COOKIE1</portal-userauthcookie>
            <portal-prelogonuserauthcookie>COOKIE2</portal-prelogonuserauthcookie>
            <config-digest>abc123</config-digest>
            <gateways>
                <external>
                    <list>
                        <entry name="gw.example.com">
                            <description>Main GW</description>
                            <priority-rule>
                                <entry name="Any"><priority>10</priority></entry>
                            </priority-rule>
                        </entry>
                    </list>
                </external>
            </gateways>
        </response>"#;

        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        assert_eq!(config.user_auth_cookie, "COOKIE1");
        assert_eq!(config.prelogon_user_auth_cookie, "COOKIE2");
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].address, "gw.example.com");
        assert_eq!(config.config_digest.as_deref(), Some("abc123"));
    }

    #[test]
    fn fallback_gateway() {
        let xml = r#"<response></response>"#;
        let config = PortalConfig::parse(xml, "portal.example.com", "alice").unwrap();
        assert_eq!(config.gateways.len(), 1);
        assert_eq!(config.gateways[0].address, "portal.example.com");
    }
}
