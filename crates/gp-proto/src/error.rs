//! Error types for GP protocol parsing.

use thiserror::Error;

/// Errors that can occur during protocol message parsing.
#[derive(Debug, Error)]
pub enum ProtoError {
    #[error("XML parse error: {0}")]
    XmlParse(String),

    #[error("missing field '{field}' in {context}")]
    MissingField {
        field: &'static str,
        context: &'static str,
    },

    #[error("unexpected response status: {0}")]
    UnexpectedStatus(String),

    #[error("protocol error: {0}")]
    Protocol(String),
}
