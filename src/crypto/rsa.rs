use ring::{rand, signature};

use crate::crypto::algorithm::AlgorithmID;
use crate::crypto::SecretOrKey;
use crate::error::{Error, ErrorDetails};
use crate::raw::*;

impl From<AlgorithmID> for &signature::RsaParameters {
    fn from(alg: AlgorithmID) -> Self {
        match alg {
            AlgorithmID::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            AlgorithmID::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            AlgorithmID::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            AlgorithmID::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
            AlgorithmID::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
            AlgorithmID::PS512 => &signature::RSA_PSS_2048_8192_SHA512,
            _ => unreachable!("Tried to get EC alg for a non-EC algorithm"),
        }
    }
}
impl From<AlgorithmID> for &dyn signature::RsaEncoding {
    fn from(alg: AlgorithmID) -> Self {
        match alg {
            AlgorithmID::RS256 => &signature::RSA_PKCS1_SHA256,
            AlgorithmID::RS384 => &signature::RSA_PKCS1_SHA384,
            AlgorithmID::RS512 => &signature::RSA_PKCS1_SHA512,
            AlgorithmID::PS256 => &signature::RSA_PSS_SHA256,
            AlgorithmID::PS384 => &signature::RSA_PSS_SHA384,
            AlgorithmID::PS512 => &signature::RSA_PSS_SHA512,
            _ => unreachable!("Tried to get RSA signature for a non-rsa algorithm"),
        }
    }
}

pub fn sign(
    algorithm: AlgorithmID,
    secret_or_key: &SecretOrKey,
    message: &str,
) -> Result<String, Error> {
    let ring_alg = algorithm.into();

    match secret_or_key {
        SecretOrKey::RsaKeyPair(key_pair) => {
            let mut signature = vec![0; key_pair.public_modulus_len()];
            let rng = rand::SystemRandom::new();
            key_pair
                .sign(ring_alg, &rng, message.as_bytes(), &mut signature)
                .map_err(|e| {
                    Error::InvalidInput(ErrorDetails::map(
                        "Failed to sign JWT with RSA",
                        Box::new(e),
                    ))
                })?;

            Ok(b64_encode(&signature))
        }
        _ => Err(Error::InvalidInput(ErrorDetails::new(
            "Missing RSA private key for signing",
        ))),
    }
}

pub fn verify(
    algorithm: AlgorithmID,
    secret_or_key: &SecretOrKey,
    message: &str,
    signature: &str,
) -> Result<(), Error> {
    match secret_or_key {
        SecretOrKey::RsaUnparsedKey(key) => {
            let ring_alg = algorithm.into();
            let public_key = signature::UnparsedPublicKey::new(ring_alg, key);
            let signature_bytes = b64_decode(signature)?;
            public_key
                .verify(message.as_bytes(), &signature_bytes)
                .map_err(|_| Error::InvalidSignature())
        }
        SecretOrKey::RsaParameters(n, e) => {
            let rsa_params = algorithm.into();
            let pubkey = signature::RsaPublicKeyComponents { n, e };
            let signature_bytes = b64_decode(signature)?;
            pubkey
                .verify(rsa_params, message.as_ref(), &signature_bytes)
                .map_err(|_| Error::InvalidSignature())
        }
        _ => Err(Error::InvalidInput(ErrorDetails::new(
            "Missing RSA public key for verifying",
        ))),
    }
}
