use std::str::FromStr;

use serde::ser::Serialize;

use crate::error::{Error, ErrorDetails};
use crate::crypto::algorithm::{Algorithm, AlgorithmID};

pub(crate) fn b64_encode(input: &[u8]) -> String {
    base64::encode_config(input, base64::URL_SAFE_NO_PAD)
}

pub(crate) fn b64_decode(input: &str) -> Result<Vec<u8>, Error> {
    base64::decode_config(input, base64::URL_SAFE_NO_PAD)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("base64 decode failure", e)))
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String, Error> {
    let json = serde_json::to_string(input)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("json serialize failure", e)))?;
    Ok(b64_encode(json.as_bytes()))
}


pub fn encode<H: Serialize, C: Serialize>(header: &H, claims: &C, algorithm: &Algorithm) -> Result<String, Error> {
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
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
    pub message: &'a str,

    /// Just the trailing signature, no '.'
    pub signature: &'a str,

    /// Just the leading header, no '.'
    pub header: &'a str,

    /// Just the claims in between the header and signature, no '.'s
    pub claims: &'a str,
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

/// Decodes a base64 encoded token header or claims and deserializes from JSON so we can run validation on it
pub(crate) fn decode_json_token_slice(encoded_slice: impl AsRef<str>) -> Result<serde_json::value::Value, Error> {
    let s = String::from_utf8(b64_decode(encoded_slice.as_ref())?)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("utf8 decode failure", e)))?;
    let value = serde_json::from_str(&s)
        .map_err(|e| Error::MalformedToken(ErrorDetails::map("json parse failure", e)))?;
    Ok(value)
}

pub fn decode_header_only(token: impl AsRef<str>) -> Result<serde_json::value::Value, Error> {
    let TokenSlices { header, .. } = split_token(token.as_ref())?;
    decode_json_token_slice(header)
}

#[derive(Debug)]
pub struct TokenData {
    pub header: serde_json::value::Value,
    pub claims: Option<serde_json::value::Value>,

    #[doc(hidden)]
    pub _extensible: (),
}

pub fn decode_only(token: impl AsRef<str>) -> Result<TokenData, Error> {
    let TokenSlices { header, claims, .. } = split_token(token.as_ref())?;
    let header = decode_json_token_slice(header)?;
    let claims = decode_json_token_slice(claims)?;
    Ok(TokenData { header: header, claims: Some(claims), _extensible: () })
}

pub fn verify_signature_only(
        header: &serde_json::value::Value,
        message: impl AsRef<str>,
        signature: impl AsRef<str>,
        algorithm: &Algorithm,
    ) -> Result<(), Error>
{
    match header.get("alg") {
        Some(serde_json::value::Value::String(alg)) => {
            let alg = AlgorithmID::from_str(alg)?;

            if alg != algorithm.get_id() {
                return Err(Error::AlgorithmMismatch());
            }

            // An Algorithm may relate to a specific 'kid' which we verify...
            let kid = match header.get("kid") {
                Some(serde_json::value::Value::String(k)) => Some(k.as_ref()),
                Some(_) => return Err(Error::MalformedToken(ErrorDetails::new("Non-string 'kid' found"))),
                None => None
            };

            algorithm.verify(kid, message, signature)?;
        },
        _ => return Err(Error::AlgorithmMismatch())
    }

    Ok(())
}