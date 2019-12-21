pub mod error;

mod verifier;
pub use verifier::*;

mod crypto;
pub use crypto::algorithm::{Algorithm, AlgorithmID};

mod pem;

pub mod raw;

mod encode;
pub use encode::encode;

pub struct TokenData {
    pub header: serde_json::value::Value,
    pub claims: serde_json::value::Value,

    #[doc(hidden)]
    pub _extensible: (),
}