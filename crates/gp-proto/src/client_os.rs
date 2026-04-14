//! Client OS spoofing configuration.

use serde::{Deserialize, Serialize};

/// The operating system identity presented to the GP server.
///
/// Defaults to [`Win`](ClientOs::Win) because many GlobalProtect deployments
/// reject or degrade Linux clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ClientOs {
    #[default]
    Win,
    Mac,
    Linux,
}

impl ClientOs {
    /// Value sent in the `clientos` form parameter.
    pub fn clientos(&self) -> &'static str {
        match self {
            Self::Win => "Windows",
            Self::Mac => "Mac",
            Self::Linux => "Linux",
        }
    }

    /// Value used with `openconnect_set_reported_os()`.
    pub fn openconnect_os(&self) -> &'static str {
        match self {
            Self::Win => "win",
            Self::Mac => "mac-intel",
            Self::Linux => "linux",
        }
    }

    /// Default User-Agent header value.
    pub fn user_agent(&self) -> &'static str {
        "PAN GlobalProtect"
    }

    /// Default OS version string matching what the real client sends.
    pub fn os_version(&self) -> &'static str {
        match self {
            Self::Win => "Microsoft Windows 10 Pro , 64-bit",
            Self::Mac => "Apple Mac OS X 13.0",
            Self::Linux => "Linux 6.1",
        }
    }
}

impl std::fmt::Display for ClientOs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Win => write!(f, "win"),
            Self::Mac => write!(f, "mac"),
            Self::Linux => write!(f, "linux"),
        }
    }
}

impl std::str::FromStr for ClientOs {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "win" | "windows" => Ok(Self::Win),
            "mac" | "macos" | "darwin" => Ok(Self::Mac),
            "linux" => Ok(Self::Linux),
            _ => Err(format!("unknown OS: {s} (expected: win, mac, linux)")),
        }
    }
}
