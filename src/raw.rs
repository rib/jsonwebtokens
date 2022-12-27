use std::str::FromStr;

use serde::ser::Serialize;

use crate::crypto::algorithm::{Algorithm, AlgorithmID};
use crate::error::{Error, ErrorDetails};
use crate::TokenData;

use base64::{engine::URL_SAFE_NO_PAD, Engine};

pub(crate) fn b64_encode(input: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(input)
}

pub(crate) fn b64_decode(input: &str) -> Result<Vec<u8>, Error> {
    URL_SAFE_NO_PAD
        .decode(input)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("base64 decode failure", Box::new(e))))
}

/// Serializes a struct to JSON and encodes it in base64
pub(crate) fn b64_encode_part<T: Serialize>(input: &T) -> Result<String, Error> {
    let json = serde_json::to_string(input).map_err(|e| {
        Error::InvalidInput(ErrorDetails::map("json serialize failure", Box::new(e)))
    })?;
    Ok(b64_encode(json.as_bytes()))
}

/// Takes the result of a str split and ensure we only get 2 parts
/// Errors if we don't
macro_rules! expect_two {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), None) => (first, second),
            _ => {
                return Err(Error::MalformedToken(ErrorDetails::new(
                    "Failed to split JWT into header.claims.signature parts",
                )))
            }
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
///
/// For example:
/// ```rust
/// # use jsonwebtokens as jwt;
/// # use jwt::raw::{self, TokenSlices};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let token = "HEADER.CLAIMS.SIGNATURE";
/// let TokenSlices {message, signature, header, claims } = raw::split_token(token)?;
/// println!("message: {}", message);
/// println!("signature: {}", signature);
/// println!("header: {}", header);
/// println!("claims: {}", claims);
/// # Ok(())
/// # }
/// ```
/// will output:
/// ```bash
/// message: HEADER.CLAIMS
/// signature: SIGNATURE
/// header: HEADER
/// claims: CLAIMS
/// ```
///
/// After splitting a token, it can be further processed by using
/// [raw::verify_signature_only](raw::verify_signature_only) to check the token's
/// signature, then [raw::decode_json_token_slice](raw::decode_json_token_slice)
/// can be used to decode the header and/or the claims, and finally the
/// [Verifier::verify_claims_only](Verifier::verify_claims_only) api can be used
/// to check the claims.
///
pub fn split_token(token: &str) -> Result<TokenSlices, Error> {
    let (signature, message) = expect_two!(token.rsplitn(2, '.'));
    let (header, claims) = expect_two!(message.splitn(2, '.'));

    Ok(TokenSlices {
        message,
        signature,
        header,
        claims,
    })
}

/// Decodes a base64 encoded token header or claims and deserializes from JSON
///
/// For example to just decode a token's header:
/// ```rust
/// # use jsonwebtokens as jwt;
/// # use jwt::raw::{self, TokenSlices, decode_json_token_slice};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
/// let TokenSlices {header, .. } = raw::split_token(token)?;
/// let header = raw::decode_json_token_slice(header)?;
/// # Ok(())
/// # }
/// ```
/// or similarly just a token's claims:
/// ```rust
/// # use jsonwebtokens as jwt;
/// # use jwt::raw::{self, TokenSlices, decode_json_token_slice};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
/// let TokenSlices {claims, .. } = raw::split_token(token)?;
/// let claims = raw::decode_json_token_slice(claims)?;
/// # Ok(())
/// # }
/// ```
pub fn decode_json_token_slice(
    encoded_slice: impl AsRef<str>,
) -> Result<serde_json::value::Value, Error> {
    let s = String::from_utf8(b64_decode(encoded_slice.as_ref())?)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("utf8 decode failure", Box::new(e))))?;
    let value = serde_json::from_str(&s)
        .map_err(|e| Error::MalformedToken(ErrorDetails::map("json parse failure", Box::new(e))))?;
    Ok(value)
}

/// Decodes just the header of a token
///
/// This just adds a little convenience over doing:
/// ```rust
/// # use jsonwebtokens as jwt;
/// # use jwt::raw::{self, TokenSlices, decode_json_token_slice};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
/// let TokenSlices {header, .. } = raw::split_token(token)?;
/// let header = raw::decode_json_token_slice(header)?;
/// # Ok(())
/// # }
/// ```
pub fn decode_header_only(token: impl AsRef<str>) -> Result<serde_json::value::Value, Error> {
    let TokenSlices { header, .. } = split_token(token.as_ref())?;
    decode_json_token_slice(header)
}

/// Decodes the header and claims of a token without any verification checks
///
/// This decodes the header and claims of a token without verifying the token's
/// signature and without verifying any of the claims.
///
/// This just adds a little convenience over doing:
/// ```rust
/// # use jsonwebtokens as jwt;
/// # use jwt::raw::{self, TokenSlices, decode_json_token_slice};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
/// let TokenSlices {header, claims, .. } = raw::split_token(token)?;
/// let header = raw::decode_json_token_slice(header)?;
/// let claims = raw::decode_json_token_slice(claims)?;
/// # Ok(())
/// # }
/// ```
pub fn decode_only(token: impl AsRef<str>) -> Result<TokenData, Error> {
    let TokenSlices { header, claims, .. } = split_token(token.as_ref())?;
    let header = decode_json_token_slice(header)?;
    let claims = decode_json_token_slice(claims)?;
    Ok(TokenData {
        header,
        claims,
        _extensible: (),
    })
}

/// Just verifies the signature of a token's message
///
/// For example:
/// ```rust
/// # use jsonwebtokens as jwt;
/// # use jwt::raw::{self, TokenSlices, decode_json_token_slice};
/// # use jwt::{AlgorithmID, Algorithm};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
/// let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
/// let TokenSlices {message, signature, header, .. } = raw::split_token(token)?;
/// let header = raw::decode_json_token_slice(header)?;
/// raw::verify_signature_only(&header, message, signature, &alg)?;
/// # Ok(())
/// # }
/// ```
pub fn verify_signature_only(
    header: &serde_json::value::Value,
    message: impl AsRef<str>,
    signature: impl AsRef<str>,
    algorithm: &Algorithm,
) -> Result<(), Error> {
    match header.get("alg") {
        Some(serde_json::value::Value::String(alg)) => {
            let alg = AlgorithmID::from_str(alg)?;

            if alg != algorithm.id() {
                return Err(Error::AlgorithmMismatch());
            }

            // An Algorithm may relate to a specific 'kid' which we verify...
            let kid = match header.get("kid") {
                Some(serde_json::value::Value::String(k)) => Some(k.as_ref()),
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(
                        "Non-string 'kid' found",
                    )))
                }
                None => None,
            };

            algorithm.verify(kid, message, signature)?;
        }
        _ => return Err(Error::AlgorithmMismatch()),
    }

    Ok(())
}
