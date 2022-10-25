use ring::{rand, signature};

use crate::crypto::algorithm::AlgorithmID;
use crate::crypto::SecretOrKey;
use crate::error::{Error, ErrorDetails};
use crate::raw::*;

impl From<AlgorithmID> for &signature::EcdsaSigningAlgorithm {
    fn from(alg: AlgorithmID) -> Self {
        match alg {
            AlgorithmID::ES256 => &signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            AlgorithmID::ES384 => &signature::ECDSA_P384_SHA384_FIXED_SIGNING,
            _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
        }
    }
}

pub fn sign(
    _algorithm: AlgorithmID,
    secret_or_key: &SecretOrKey,
    message: &str,
) -> Result<String, Error> {
    match secret_or_key {
        SecretOrKey::EcdsaKeyPair(signing_key) => {
            let rng = rand::SystemRandom::new();
            let out = signing_key.sign(&rng, message.as_bytes()).map_err(|e| {
                Error::InvalidInput(ErrorDetails::map(
                    "Failed to sign JWT with ECDSA",
                    Box::new(e),
                ))
            })?;
            Ok(b64_encode(out.as_ref()))
        }
        _ => Err(Error::InvalidInput(ErrorDetails::new(
            "Missing ECDSA private key for signing",
        ))),
    }
}

pub fn verify(
    algorithm: AlgorithmID,
    secret_or_key: &SecretOrKey,
    message: &str,
    signature: &str,
) -> Result<(), Error> {
    let ring_alg = algorithm.into();
    match secret_or_key {
        SecretOrKey::EcdsaUnparsedKey(key) => {
            let public_key = signature::UnparsedPublicKey::new(ring_alg, key);
            let signature_bytes = b64_decode(signature)?;
            public_key
                .verify(message.as_bytes(), &signature_bytes)
                .map_err(|_| Error::InvalidSignature())
        }
        _ => Err(Error::InvalidInput(ErrorDetails::new(
            "Missing ECDSA public key for signing",
        ))),
    }
}
