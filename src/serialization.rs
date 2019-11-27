use serde::ser::Serialize;
use serde_json::map::Map;
use serde_json::{from_str, to_string, Value};

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
    let json = to_string(input)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("json serialize failure", e)))?;
    Ok(b64_encode(json.as_bytes()))
}

/// Decodes from base64 and deserializes from JSON so we can run validation on it
pub(crate) fn parse_jwt_part<B: AsRef<str>>(encoded: B) -> Result<Map<String, Value>, Error> {
    let s = String::from_utf8(b64_decode(encoded.as_ref())?)
        .map_err(|e| Error::InvalidInput(ErrorDetails::map("utf8 decode failure", e)))?;
    let json_map: Map<_, _> = from_str(&s)
        .map_err(|e| Error::MalformedToken(ErrorDetails::map("json parse failure", e)))?;
    Ok(json_map)
}
