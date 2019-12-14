use serde_json::map::Map;
use serde_json::value::Value;

pub mod error;
use error::{Error, ErrorDetails};

mod verifier;
pub use verifier::*;

mod crypto;
pub use crypto::algorithm::{Algorithm, AlgorithmID};

mod pem;
mod serialization;
use serialization::parse_jwt_part;

use serde::ser::Serialize;

pub fn encode<H: Serialize, C: Serialize>(header: &H, claims: &C, algorithm: &Algorithm) -> Result<String, Error> {
    let encoded_header = serialization::b64_encode_part(&header)?;
    let encoded_claims = serialization::b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = algorithm.sign(&message)?;
    Ok([message, signature].join("."))
}

/// Takes the result of a str split and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => return Err(Error::MalformedToken(ErrorDetails::new("Failed to split JWT into header.claims.signature parts"))),
        }
    }};
}

pub struct TokenSlices<'a> {
    /// The header and claims (including adjoining '.') but not the last '.' or signature
    message: &'a str,

    /// Just the trailing signature, no '.'
    signature: &'a str,

    /// Just the leading header, no '.'
    header: &'a str,

    /// Just the claims in between the header and signature, no '.'s
    claims: &'a str,
}

/// Splits a token that's in the form `"HEADER.CLAIMS.SIGNATURE"` into useful constituent
/// parts for further parsing and validation.
pub fn split_token<'a>(token: &'a str) -> Result<TokenSlices<'a>, Error> {
    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (header, claims) = expect_two!(message.splitn(2, '.'));

    Ok(TokenSlices {
        message,
        signature,
        header,
        claims
    })
}

#[derive(Debug)]
pub struct TokenData {
    pub header: Map<String, Value>,
    pub claims: Option<Map<String, Value>>,

    #[doc(hidden)]
    _extensible: (),
}

pub fn decode_header_only(token: impl AsRef<str>) -> Result<Map<String, Value>, Error> {
    let TokenSlices { header, .. } = split_token(token.as_ref())?;
    parse_jwt_part(header)
}

pub fn decode_only(token: impl AsRef<str>) -> Result<TokenData, Error> {
    let TokenSlices { header, claims, .. } = split_token(token.as_ref())?;
    let header = parse_jwt_part(header)?;
    let claims = parse_jwt_part(claims)?;
    Ok(TokenData { header: header, claims: Some(claims), _extensible: () })
}