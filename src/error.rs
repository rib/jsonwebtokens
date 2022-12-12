use std::error::Error as StdError;
use std::fmt;

#[derive(Debug)]
#[non_exhaustive]
pub struct ErrorDetails {
    desc: String,
    src: Option<Box<dyn StdError + Send + Sync + 'static>>,
}

impl ErrorDetails {
    pub fn new(desc: impl Into<String>) -> ErrorDetails {
        ErrorDetails {
            desc: desc.into(),
            src: None,
        }
    }

    pub fn map(
        desc: impl Into<String>,
        src: Box<dyn StdError + Send + Sync + 'static>,
    ) -> ErrorDetails {
        ErrorDetails {
            desc: desc.into(),
            src: Some(src),
        }
    }
}

impl From<String> for ErrorDetails {
    fn from(s: String) -> Self {
        ErrorDetails { desc: s, src: None }
    }
}

#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// Any of: invalid key data, malformed data for encoding, base864/utf8 decode/encode errors
    InvalidInput(ErrorDetails),

    /// The alg found in the token header didn't match the given algorithm
    AlgorithmMismatch(),

    /// The token's signature was not validated
    InvalidSignature(),

    /// The token expired at this time (unix epoch timestamp)
    TokenExpiredAt(u64),

    /// Any of: header.payload.signature split error, json parser error, header or claim validation error
    MalformedToken(ErrorDetails),
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::InvalidInput(ErrorDetails { src: Some(s), .. }) => Some(s.as_ref()),
            Error::AlgorithmMismatch() => None,
            Error::InvalidSignature() => None,
            Error::TokenExpiredAt(_) => None,
            Error::MalformedToken(ErrorDetails { src: Some(s), .. }) => Some(s.as_ref()),
            _ => None,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidInput(details) => write!(f, "Invalid Input: {}", details.desc),
            Error::AlgorithmMismatch() => write!(f, "JWT Algorithm Mismatch"),
            Error::InvalidSignature() => write!(f, "JWT Signature Invalid"),
            Error::TokenExpiredAt(when) => write!(f, "JWT token expired at {when}"),
            Error::MalformedToken(details) => write!(f, "JWT claims invalid: {}", details.desc),
        }
    }
}
