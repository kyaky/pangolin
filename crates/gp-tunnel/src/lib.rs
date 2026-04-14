//! Tunnel management — safe Rust wrapper around `libopenconnect`.
//!
//! Provides [`OpenConnectSession`] which manages the lifecycle of a VPN
//! tunnel: session creation, protocol selection, authcookie injection,
//! CSTP/TUN setup, blocking main loop, and cancellation.

use thiserror::Error;

mod openconnect;

pub use openconnect::{CancelHandle, OpenConnectSession};

/// Tunnel errors.
#[derive(Debug, Error)]
pub enum TunnelError {
    #[error("openconnect error: {0}")]
    OpenConnect(String),

    #[error("tunnel not connected")]
    NotConnected,
}
