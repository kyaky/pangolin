//! Pangolin configuration file (`config.toml`) and credential store (keyring).

use std::collections::HashMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Configuration errors.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("config file not found: {0}")]
    NotFound(PathBuf),

    #[error("config parse error: {0}")]
    Parse(String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Top-level pangolin configuration (`~/.config/pangolin/config.toml`).
///
/// ```toml
/// [default]
/// os = "win"
/// reconnect = true
///
/// [portal.work]
/// url = "vpn.example.com"
/// username = "alice"
/// ```
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PangolinConfig {
    /// Global defaults.
    #[serde(default)]
    pub default: DefaultConfig,

    /// Named portal profiles.
    #[serde(default)]
    pub portal: HashMap<String, PortalProfile>,
}

/// Global default settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DefaultConfig {
    /// OS to spoof (`"win"`, `"mac"`, `"linux"`).
    #[serde(default = "default_os")]
    pub os: String,

    /// Automatically reconnect on disconnect.
    #[serde(default = "default_true")]
    pub reconnect: bool,
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            os: default_os(),
            reconnect: true,
        }
    }
}

/// A named portal connection profile.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PortalProfile {
    /// Portal hostname or URL.
    pub url: String,

    /// Default username.
    #[serde(default)]
    pub username: Option<String>,

    /// Preferred gateway address.
    #[serde(default)]
    pub gateway: Option<String>,
}

fn default_os() -> String {
    "win".into()
}
fn default_true() -> bool {
    true
}

impl PangolinConfig {
    /// Load configuration from the default path, returning defaults if the
    /// file does not exist.
    pub fn load() -> Result<Self, ConfigError> {
        let path = Self::default_path();
        if !path.exists() {
            return Ok(Self::default());
        }
        let contents = std::fs::read_to_string(&path)?;
        toml::from_str(&contents).map_err(|e| ConfigError::Parse(e.to_string()))
    }

    /// Platform-appropriate config file path.
    pub fn default_path() -> PathBuf {
        directories::ProjectDirs::from("", "", "pangolin")
            .map(|d| d.config_dir().join("config.toml"))
            .unwrap_or_else(|| PathBuf::from("config.toml"))
    }

    /// Look up a portal profile by name or by URL.
    pub fn find_portal(&self, name_or_url: &str) -> Option<&PortalProfile> {
        if let Some(profile) = self.portal.get(name_or_url) {
            return Some(profile);
        }
        self.portal.values().find(|p| p.url == name_or_url)
    }
}
