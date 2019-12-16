
use serde::ser::Serialize;

use crate::error::Error;
use crate::raw::*;
use crate::crypto::algorithm::Algorithm;


pub fn encode<H: Serialize, C: Serialize>(header: &H, claims: &C, algorithm: &Algorithm) -> Result<String, Error> {
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = algorithm.sign(&message)?;
    Ok([message, signature].join("."))
}