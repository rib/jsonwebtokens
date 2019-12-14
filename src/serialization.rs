use serde::ser::Serialize;

use crate::error::{Error, ErrorDetails};

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

/// Decodes from base64 and deserializes from JSON so we can run validation on it
pub(crate) fn decode_json_token_slice(encoded_slice: impl AsRef<str>) -> Result<serde_json::value::Value, Error> {
    let s = String::from_utf8(b64_decode(encoded_slice.as_ref())?)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("utf8 decode failure", e)))?;
    let value = serde_json::from_str(&s)
        .map_err(|e| Error::MalformedToken(ErrorDetails::map("json parse failure", e)))?;
    Ok(value)
}
