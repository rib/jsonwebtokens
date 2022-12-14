use ring::signature;
use serde::{Deserialize, Serialize};
use simple_asn1::BigUint;
use std::fmt;
use std::str::FromStr;

use crate::crypto::*;
use crate::error::{Error, ErrorDetails};
use crate::pem::decoder::PemEncodedKey;
use crate::raw::*;

impl From<AlgorithmID> for &dyn signature::VerificationAlgorithm {
    fn from(alg: AlgorithmID) -> Self {
        match alg {
            AlgorithmID::ES256 => &signature::ECDSA_P256_SHA256_FIXED,
            AlgorithmID::ES384 => &signature::ECDSA_P384_SHA384_FIXED,

            AlgorithmID::RS256 => &signature::RSA_PKCS1_2048_8192_SHA256,
            AlgorithmID::RS384 => &signature::RSA_PKCS1_2048_8192_SHA384,
            AlgorithmID::RS512 => &signature::RSA_PKCS1_2048_8192_SHA512,
            AlgorithmID::PS256 => &signature::RSA_PSS_2048_8192_SHA256,
            AlgorithmID::PS384 => &signature::RSA_PSS_2048_8192_SHA384,
            AlgorithmID::PS512 => &signature::RSA_PSS_2048_8192_SHA512,

            _ => unreachable!("algorithm doesn't map to a ring signature verification algorithm"),
        }
    }
}

/// Uniquely identifies a specific cryptographic algorithm for signing or verifying tokens
#[derive(Debug, PartialEq, Eq, Copy, Clone, Serialize, Deserialize)]
#[non_exhaustive]
pub enum AlgorithmID {
    /// Unsecured JWT
    NONE,

    /// HMAC using SHA-256
    HS256,
    /// HMAC using SHA-384
    HS384,
    /// HMAC using SHA-512
    HS512,

    /// ECDSA using SHA-256
    ES256,
    /// ECDSA using SHA-384
    ES384,

    /// RSASSA-PKCS1-v1_5 using SHA-256
    RS256,
    /// RSASSA-PKCS1-v1_5 using SHA-384
    RS384,
    /// RSASSA-PKCS1-v1_5 using SHA-512
    RS512,

    /// RSASSA-PSS using SHA-256
    PS256,
    /// RSASSA-PSS using SHA-384
    PS384,
    /// RSASSA-PSS using SHA-512
    PS512,
}

impl From<AlgorithmID> for &'static str {
    fn from(id: AlgorithmID) -> Self {
        match id {
            AlgorithmID::NONE => "none",

            AlgorithmID::HS256 => "HS256",
            AlgorithmID::HS384 => "HS384",
            AlgorithmID::HS512 => "HS512",

            AlgorithmID::ES256 => "ES256",
            AlgorithmID::ES384 => "ES384",

            AlgorithmID::RS256 => "RS256",
            AlgorithmID::RS384 => "RS384",
            AlgorithmID::RS512 => "RS512",

            AlgorithmID::PS256 => "PS256",
            AlgorithmID::PS384 => "PS384",
            AlgorithmID::PS512 => "PS512",
        }
    }
}

impl std::fmt::Display for AlgorithmID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg = *self;
        let s: &'static str = alg.into();
        write!(f, "{s}")
    }
}

impl FromStr for AlgorithmID {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "none" => Ok(AlgorithmID::NONE),

            "HS256" => Ok(AlgorithmID::HS256),
            "HS384" => Ok(AlgorithmID::HS384),
            "HS512" => Ok(AlgorithmID::HS512),

            "ES256" => Ok(AlgorithmID::ES256),
            "ES384" => Ok(AlgorithmID::ES384),

            "RS256" => Ok(AlgorithmID::RS256),
            "RS384" => Ok(AlgorithmID::RS384),
            "RS512" => Ok(AlgorithmID::RS512),

            "PS256" => Ok(AlgorithmID::PS256),
            "PS384" => Ok(AlgorithmID::PS384),
            "PS512" => Ok(AlgorithmID::PS512),

            _ => Err(Error::InvalidInput(ErrorDetails::new(format!(
                "Unknown algorithm name {s}"
            )))),
        }
    }
}

impl From<Algorithm> for &'static str {
    fn from(alg: Algorithm) -> Self {
        alg.name()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_algorithm_enum_from_str() {
        assert!(AlgorithmID::from_str("none").is_ok());

        assert!(AlgorithmID::from_str("HS256").is_ok());
        assert!(AlgorithmID::from_str("HS384").is_ok());
        assert!(AlgorithmID::from_str("HS512").is_ok());

        assert!(AlgorithmID::from_str("ES256").is_ok());
        assert!(AlgorithmID::from_str("ES384").is_ok());

        assert!(AlgorithmID::from_str("RS256").is_ok());
        assert!(AlgorithmID::from_str("RS384").is_ok());
        assert!(AlgorithmID::from_str("RS512").is_ok());

        assert!(AlgorithmID::from_str("PS256").is_ok());
        assert!(AlgorithmID::from_str("PS384").is_ok());
        assert!(AlgorithmID::from_str("PS512").is_ok());

        assert!(AlgorithmID::from_str("").is_err());
    }
}

fn ensure_hmac_id(id: AlgorithmID) -> Result<(), Error> {
    match id {
        AlgorithmID::HS256 => Ok(()),
        AlgorithmID::HS384 => Ok(()),
        AlgorithmID::HS512 => Ok(()),
        _ => Err(Error::AlgorithmMismatch()),
    }
}

fn ensure_ecdsa_id(id: AlgorithmID) -> Result<(), Error> {
    match id {
        AlgorithmID::ES256 => Ok(()),
        AlgorithmID::ES384 => Ok(()),
        _ => Err(Error::AlgorithmMismatch()),
    }
}

fn ensure_rsa_id(id: AlgorithmID) -> Result<(), Error> {
    match id {
        AlgorithmID::RS256 => Ok(()),
        AlgorithmID::RS384 => Ok(()),
        AlgorithmID::RS512 => Ok(()),

        AlgorithmID::PS256 => Ok(()),
        AlgorithmID::PS384 => Ok(()),
        AlgorithmID::PS512 => Ok(()),
        _ => Err(Error::AlgorithmMismatch()),
    }
}

/// A cryptographic function for signing or verifying a token signature
///
/// An Algorithm encapsulates one function for signing or verifying tokens. A key
/// or secret only needs to be decoded once so it can be reused cheaply while
/// signing or verifying tokens. The decoded key or secret and `AlgorithmID` are
/// immutable after construction to avoid the chance of being coerced into using
/// the wrong algorithm to sign or verify a token at runtime.
///
/// Optionally a `kid` Key ID can be assigned to an `Algorithm` to add a strict
/// check that a token's header must include the same `kid` value. This is useful
/// when using an `Algorithm` to represent a single key within a JWKS key set,
/// for example.
///
#[derive(Debug)]
pub struct Algorithm {
    id: AlgorithmID,
    kid: Option<String>,

    secret_or_key: SecretOrKey,
}

impl Algorithm {
    /// Returns the `AlgorithmID` that was used to construct the `Algorithm`
    pub fn id(&self) -> AlgorithmID {
        self.id
    }

    /// Returns the algorithm name as standardized in [RFC 7518](https://tools.ietf.org/html/rfc7518)
    pub fn name(&self) -> &'static str {
        self.id.into()
    }

    /// Optionally if a `kid` is associated with an algorithm there will be an extra
    /// verification that a token's kid matches the one associated with the `Algorithm`
    pub fn set_kid(&mut self, kid: impl Into<String>) {
        self.kid = Some(kid.into());
    }

    /// Returns a reference to any associated `kid` set via `set_kid()`
    pub fn kid(&self) -> Option<&str> {
        match &self.kid {
            Some(string) => Some(string.as_ref()),
            None => None,
        }
    }

    /// Constructs a NOP algorithm for use with unsecured (unsigned) tokens
    pub fn new_unsecured() -> Result<Self, Error> {
        Ok(Algorithm {
            id: AlgorithmID::NONE,
            kid: None,
            secret_or_key: SecretOrKey::None,
        })
    }

    /// Constructs a symmetric HMAC algorithm based on a given secret
    ///
    /// This algorithm may be used for signing and/or verifying signatures
    pub fn new_hmac(id: AlgorithmID, secret: impl Into<Vec<u8>>) -> Result<Self, Error> {
        ensure_hmac_id(id)?;

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::Secret(secret.into()),
        })
    }

    /// Constructs a symmetric HMAC algorithm based on a given base64 secret
    ///
    /// This is a convenience api in case the secret you're using is base64 encoded
    ///
    /// This algorithm may be used for signing and/or verifying signatures
    pub fn new_hmac_b64(id: AlgorithmID, secret: impl AsRef<str>) -> Result<Self, Error> {
        ensure_hmac_id(id)?;

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::Secret(b64_decode(secret.as_ref())?),
        })
    }

    /// Constructs an ECDSA algorithm based on a PEM format private key
    ///
    /// This algorithm may only be used for signing tokens
    pub fn new_ecdsa_pem_signer(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_ecdsa_id(id)?;

        let ring_alg = id.into();
        let pem_key = PemEncodedKey::new(key)?;
        let signing_key =
            signature::EcdsaKeyPair::from_pkcs8(ring_alg, pem_key.as_ec_private_key()?).map_err(
                |e| {
                    Error::InvalidInput(ErrorDetails::map(
                        "Failed to create ECDSA key pair for signing",
                        Box::new(e),
                    ))
                },
            )?;

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::EcdsaKeyPair(Box::from(signing_key)),
        })
    }

    /// Constructs an ECDSA algorithm based on a PEM format public key
    ///
    /// This algorithm may only be used for verifying tokens
    pub fn new_ecdsa_pem_verifier(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_ecdsa_id(id)?;

        let pem_key = PemEncodedKey::new(key)?;
        let ec_pub_key = pem_key.as_ec_public_key()?;

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::EcdsaUnparsedKey(ec_pub_key.to_vec()),
        })
    }

    /// Constructs an RSA algorithm based on a PEM format private key
    ///
    /// This algorithm may only be used for signing tokens
    pub fn new_rsa_pem_signer(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_rsa_id(id)?;

        let pem_key = PemEncodedKey::new(key)?;
        let key_pair =
            signature::RsaKeyPair::from_der(pem_key.as_rsa_private_key()?).map_err(|e| {
                Error::InvalidInput(ErrorDetails::map(
                    "Failed to create RSA key for signing",
                    Box::new(e),
                ))
            })?;

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::RsaKeyPair(Box::from(key_pair)),
        })
    }

    /// Constructs an RSA algorithm based on a PEM format public key
    ///
    /// This algorithm may only be used for verifying tokens
    pub fn new_rsa_pem_verifier(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_rsa_id(id)?;

        let pem_key = PemEncodedKey::new(key)?;
        let rsa_pub_key = pem_key.as_rsa_public_key()?;

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::RsaUnparsedKey(rsa_pub_key.to_vec()),
        })
    }

    /// Constructs an RSA algorithm based on modulus (n) and exponent (e) components
    ///
    /// In some situations (such as JWKS key sets), a public RSA key may be
    /// described in terms of (base64 encoded) modulus and exponent values.
    ///
    /// This algorithm may only be used for verifying tokens
    pub fn new_rsa_n_e_b64_verifier(
        id: AlgorithmID,
        n_b64: &str,
        e_b64: &str,
    ) -> Result<Self, Error> {
        ensure_rsa_id(id)?;

        let n = BigUint::from_bytes_be(&b64_decode(n_b64)?).to_bytes_be();
        let e = BigUint::from_bytes_be(&b64_decode(e_b64)?).to_bytes_be();

        Ok(Algorithm {
            id,
            kid: None,
            secret_or_key: SecretOrKey::RsaParameters(n, e),
        })
    }

    /// Lower-level api that can be used to verify a signature for a given message
    pub fn verify(
        &self,
        kid: Option<&str>,
        message: impl AsRef<str>,
        signature: impl AsRef<str>,
    ) -> Result<(), Error> {
        // We need an Option(&str) instead of Option(String)
        let kid_matches = match &self.kid {
            Some(string) => kid == Some(string.as_ref()),
            None => true,
        };
        if !kid_matches {
            return Err(Error::MalformedToken(ErrorDetails::new(format!(
                "'kid' ({:?}) didn't match ID ({:?}) associated with Algorithm",
                kid, self.kid
            ))));
        }

        match self.id {
            AlgorithmID::NONE => {
                if signature.as_ref() == "" {
                    Ok(())
                } else {
                    Err(Error::InvalidSignature())
                }
            }
            AlgorithmID::HS256 | AlgorithmID::HS384 | AlgorithmID::HS512 => hmac::verify(
                self.id,
                &self.secret_or_key,
                message.as_ref(),
                signature.as_ref(),
            ),
            AlgorithmID::ES256 | AlgorithmID::ES384 => ecdsa::verify(
                self.id,
                &self.secret_or_key,
                message.as_ref(),
                signature.as_ref(),
            ),
            AlgorithmID::RS256
            | AlgorithmID::RS384
            | AlgorithmID::RS512
            | AlgorithmID::PS256
            | AlgorithmID::PS384
            | AlgorithmID::PS512 => rsa::verify(
                self.id,
                &self.secret_or_key,
                message.as_ref(),
                signature.as_ref(),
            ),
        }
    }

    /// Lower-level api that can be used to calculate a signature for a message
    pub fn sign(&self, message: &str) -> Result<String, Error> {
        match self.id {
            AlgorithmID::NONE => Ok("".to_owned()),
            AlgorithmID::HS256 | AlgorithmID::HS384 | AlgorithmID::HS512 => {
                hmac::sign(self.id, &self.secret_or_key, message)
            }
            AlgorithmID::ES256 | AlgorithmID::ES384 => {
                ecdsa::sign(self.id, &self.secret_or_key, message)
            }
            AlgorithmID::RS256
            | AlgorithmID::RS384
            | AlgorithmID::RS512
            | AlgorithmID::PS256
            | AlgorithmID::PS384
            | AlgorithmID::PS512 => rsa::sign(self.id, &self.secret_or_key, message),
        }
    }
}
