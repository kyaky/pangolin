//! Tunnel configuration parsed from gateway `getconfig.esp`.

use crate::error::ProtoError;
use crate::xml::XmlNode;

/// Configuration returned by the gateway for tunnel setup.
///
/// Parsed from `/ssl-vpn/getconfig.esp`. In practice openconnect handles
/// most of this internally, but we parse the fields needed for HIP checks
/// and status display.
#[derive(Debug, Clone)]
pub struct TunnelConfig {
    /// Client IP assigned by the gateway.
    pub client_ip: Option<String>,
    /// Whether HIP report submission is required.
    pub hip_report_needed: bool,
    /// MTU for the tunnel interface.
    pub mtu: Option<u32>,
    /// DNS servers pushed by the gateway.
    pub dns_servers: Vec<String>,
    /// DNS suffixes / search domains.
    pub dns_suffixes: Vec<String>,
}

impl TunnelConfig {
    /// Parse from the XML body of `/ssl-vpn/getconfig.esp`.
    pub fn parse(xml: &str) -> Result<Self, ProtoError> {
        let root = XmlNode::parse(xml)?;

        let client_ip = root.find_text("ip-address").map(|s| s.to_string());

        let hip_report_needed = root
            .find_text("hip-report-needed")
            .map(|s| s.eq_ignore_ascii_case("yes"))
            .unwrap_or(false);

        let mtu = root.find_text("mtu").and_then(|s| s.parse::<u32>().ok());

        let dns_servers = root
            .find("dns")
            .map(|dns| {
                dns.children_named("member")
                    .filter(|m| !m.text.is_empty())
                    .map(|m| m.text.clone())
                    .collect()
            })
            .unwrap_or_default();

        let dns_suffixes = root
            .find("dns-suffix")
            .map(|ds| {
                ds.children_named("member")
                    .filter(|m| !m.text.is_empty())
                    .map(|m| m.text.clone())
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            client_ip,
            hip_report_needed,
            mtu,
            dns_servers,
            dns_suffixes,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_tunnel_config() {
        let xml = r#"
        <response>
            <ip-address>10.0.0.42</ip-address>
            <hip-report-needed>yes</hip-report-needed>
            <mtu>1400</mtu>
            <dns>
                <member>8.8.8.8</member>
                <member>8.8.4.4</member>
            </dns>
            <dns-suffix>
                <member>corp.example.com</member>
            </dns-suffix>
        </response>"#;

        let cfg = TunnelConfig::parse(xml).unwrap();
        assert_eq!(cfg.client_ip.as_deref(), Some("10.0.0.42"));
        assert!(cfg.hip_report_needed);
        assert_eq!(cfg.mtu, Some(1400));
        assert_eq!(cfg.dns_servers, vec!["8.8.8.8", "8.8.4.4"]);
        assert_eq!(cfg.dns_suffixes, vec!["corp.example.com"]);
    }
}
