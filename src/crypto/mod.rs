
use std::fmt;
use std::str::FromStr;
use ring::signature;
use serde::{Deserialize, Serialize};
use simple_asn1::BigUint;

use crate::error::{Error, ErrorDetails};
use crate::serialization::b64_decode;
use crate::pem::decoder::PemEncodedKey;

pub(crate) mod hmac;
pub(crate) mod ecdsa;
pub(crate) mod rsa;

#[derive(Debug)]
pub enum SecretOrKey {
    // Unsecured
    None,

    // HMAC
    Secret(Vec<u8>),

    // ECDSA
    EcdsaKeyPair(signature::EcdsaKeyPair),
    EcdsaUnparsedKey(Vec<u8>),

    // RSA
    RsaKeyPair(signature::RsaKeyPair),
    RsaUnparsedKey(Vec<u8>),
    RsaParameters(Vec<u8>, Vec<u8>), // (n, e)
}

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


#[derive(Debug, PartialEq, Copy, Clone, Serialize, Deserialize)]
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

    #[doc(hidden)]
    __Nonexhaustive
}

impl Default for AlgorithmID {
    fn default() -> Self {
        AlgorithmID::HS256
    }
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

            __nonexhaustive => "Unknown"
        }
    }
}

impl std::fmt::Display for AlgorithmID {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let alg = *self;
        let s: &'static str = alg.into();
        write!(f, "{}", s)
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

            _ => Err(Error::InvalidInput(ErrorDetails::new(format!("Unknown algorithm name {}", s)))),
        }
    }
}

impl From<Algorithm> for &'static str {
    fn from(alg: Algorithm) -> Self {
        alg.get_jwt_name()
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

fn ensure_hmac_id(id: AlgorithmID) -> Result<(), Error>
{
    match id {
        AlgorithmID::HS256 => Ok(()),
        AlgorithmID::HS384 => Ok(()),
        AlgorithmID::HS512 => Ok(()),
        _ => Err(Error::AlgorithmMismatch())
    }
}

fn ensure_ecdsa_id(id: AlgorithmID) -> Result<(), Error>
{
    match id {
        AlgorithmID::ES256 => Ok(()),
        AlgorithmID::ES384 => Ok(()),
        _ => Err(Error::AlgorithmMismatch())
    }
}

fn ensure_rsa_id(id: AlgorithmID) -> Result<(), Error>
{
    match id {
        AlgorithmID::RS256 => Ok(()),
        AlgorithmID::RS384 => Ok(()),
        AlgorithmID::RS512 => Ok(()),

        AlgorithmID::PS256 => Ok(()),
        AlgorithmID::PS384 => Ok(()),
        AlgorithmID::PS512 => Ok(()),
        _ => Err(Error::AlgorithmMismatch())
    }
}

// The idea is that by having a trait based around an async API we make it easy to support
// validating based on a remote (jwks) key set
// (Not possible yet though because we can't have async functions in traits)
/*
pub trait TokenSignatureVerifier
{
    async fn verify(header: &Header, message: &str, signature: &str) -> Result<bool, Error>;
}
*/

#[derive(Debug)]
pub struct Algorithm
{
    id: AlgorithmID,

    secret_or_key: SecretOrKey,

    #[doc(hidden)]
    _extensible: (),
}

impl Algorithm
{
    pub fn get_id(&self) -> AlgorithmID {
        self.id
    }

    pub fn get_jwt_name(&self) -> &'static str {
        self.id.into()
    }

    pub fn new_unsecured() -> Result<Self, Error> {
        Ok(Algorithm {
            id: AlgorithmID::NONE,
            secret_or_key: SecretOrKey::None,
            _extensible: ()
        })
    }

    pub fn new_hmac(id: AlgorithmID, secret: impl Into<Vec<u8>>) -> Result<Self, Error> {
        ensure_hmac_id(id)?;

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::Secret(secret.into()),
            _extensible: ()
        })
    }
    pub fn new_hmac_b64(id: AlgorithmID, secret: impl AsRef<str>) -> Result<Self, Error> {
        ensure_hmac_id(id)?;

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::Secret(b64_decode(secret.as_ref())?),
            _extensible: ()
        })
    }

    pub fn new_ecdsa_pem_signer(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_ecdsa_id(id)?;

        let ring_alg = id.into();
        let pem_key = PemEncodedKey::new(key)?;
        let signing_key = signature::EcdsaKeyPair::from_pkcs8(ring_alg, pem_key.as_ec_private_key()?)
            .map_err(|e| Error::InvalidInput(ErrorDetails::map("Failed to create ECDSA key pair for signing", e)))?;

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::EcdsaKeyPair(signing_key),
            _extensible: ()
        })
    }
    pub fn new_ecdsa_pem_verifier(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_ecdsa_id(id)?;

        let pem_key = PemEncodedKey::new(key)?;
        let ec_pub_key = pem_key.as_ec_public_key()?;

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::EcdsaUnparsedKey(ec_pub_key.to_vec()),
            _extensible: ()
        })
    }

    pub fn new_rsa_pem_signer(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_rsa_id(id)?;

        let pem_key = PemEncodedKey::new(key)?;
        let key_pair = signature::RsaKeyPair::from_der(pem_key.as_rsa_private_key()?)
            .map_err(|e| Error::InvalidInput(ErrorDetails::map("Failed to create RSA key for signing", e)))?;

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::RsaKeyPair(key_pair),
            _extensible: ()
        })
    }
    pub fn new_rsa_pem_verifier(id: AlgorithmID, key: &[u8]) -> Result<Self, Error> {
        ensure_rsa_id(id)?;

        let pem_key = PemEncodedKey::new(key)?;
        let rsa_pub_key = pem_key.as_rsa_public_key()?;

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::RsaUnparsedKey(rsa_pub_key.to_vec()),
            _extensible: ()
        })
    }
    pub fn new_rsa_n_e_b64_verifier(id: AlgorithmID, n_b64: &str, e_b64: &str) -> Result<Self, Error> {
        ensure_rsa_id(id)?;

        let n = BigUint::from_bytes_be(&b64_decode(n_b64)?).to_bytes_be();
        let e = BigUint::from_bytes_be(&b64_decode(e_b64)?).to_bytes_be();

        Ok(Algorithm {
            id: id,
            secret_or_key: SecretOrKey::RsaParameters(n, e),
            _extensible: ()
        })
    }

    pub async fn verify(
        &self,
        _kid: Option<&str>,
        message: impl AsRef<str>,
        signature: impl AsRef<str>)
    -> Result<(), Error> {
        match self.id {
            AlgorithmID::HS256 | AlgorithmID::HS384 | AlgorithmID::HS512 => {
                hmac::verify(self.id, &self.secret_or_key, message.as_ref(), signature.as_ref())
            }
            AlgorithmID::ES256 | AlgorithmID::ES384 => {
                ecdsa::verify(self.id, &self.secret_or_key, message.as_ref(), signature.as_ref())
            }
            AlgorithmID::RS256
            | AlgorithmID::RS384
            | AlgorithmID::RS512
            | AlgorithmID::PS256
            | AlgorithmID::PS384
            | AlgorithmID::PS512 => {
                rsa::verify(self.id, &self.secret_or_key, message.as_ref(), signature.as_ref())
            }
            AlgorithmID::__Nonexhaustive => unreachable!("unhandled algorithm"),
        }
    }

    pub async fn sign(
        &self,
        _kid: Option<&str>,
        message: &str)
    -> Result<String, Error> {
        match self.id {
            AlgorithmID::HS256 | AlgorithmID::HS384 | AlgorithmID::HS512 => {
                hmac::sign(self.id, &self.secret_or_key, message)
            },
            AlgorithmID::ES256 | AlgorithmID::ES384 => {
                ecdsa::sign(self.id, &self.secret_or_key, message)
            }
            AlgorithmID::RS256
            | AlgorithmID::RS384
            | AlgorithmID::RS512
            | AlgorithmID::PS256
            | AlgorithmID::PS384
            | AlgorithmID::PS512 => {
                rsa::sign(self.id, &self.secret_or_key, message)
            }
            AlgorithmID::__Nonexhaustive => unreachable!("unhandled algorithm"),
        }
    }
}
