use crate::crypto::algorithm::AlgorithmID;
use crate::crypto::SecretOrKey;
use crate::error::{Error, ErrorDetails};
use crate::raw::*;
use ring::constant_time::verify_slices_are_equal;
use ring::hmac;

impl From<AlgorithmID> for hmac::Algorithm {
    fn from(alg: AlgorithmID) -> Self {
        match alg {
            AlgorithmID::HS256 => ring::hmac::HMAC_SHA256,
            AlgorithmID::HS384 => ring::hmac::HMAC_SHA384,
            AlgorithmID::HS512 => ring::hmac::HMAC_SHA512,
            _ => unreachable!("Tried to map HMAC type for a non-HMAC algorithm"),
        }
    }
}

pub(crate) fn sign(
    alg: AlgorithmID,
    secret_or_key: &SecretOrKey,
    message: &str,
) -> Result<String, Error> {
    match secret_or_key {
        SecretOrKey::Secret(key) => {
            let ring_alg = alg.into();
            let digest = hmac::sign(&hmac::Key::new(ring_alg, key), message.as_bytes());
            Ok(b64_encode(digest.as_ref()))
        }
        _ => Err(Error::InvalidInput(ErrorDetails::new(
            "Missing secret for HMAC signing",
        ))),
    }
}

pub fn verify(
    algorithm: AlgorithmID,
    secret_or_key: &SecretOrKey,
    message: &str,
    signature: &str,
) -> Result<(), Error> {
    // we just re-sign the message with the key and compare if they are equal
    let signed = sign(algorithm, secret_or_key, message)?;
    verify_slices_are_equal(signature.as_bytes(), signed.as_ref())
        .map_err(|_| Error::InvalidSignature())
}
