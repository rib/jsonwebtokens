use serde::ser::Serialize;

use crate::crypto::algorithm::Algorithm;
use crate::error::Error;
use crate::raw::*;

/// Encodes a Json Web Token
///
/// For example, to encode and sign a token with a symmetric secret:
/// ```rust
/// # use serde_json::json;
/// # use serde_json::value::Value;
/// # use jsonwebtokens as jwt;
/// # use jwt::{Algorithm, AlgorithmID, Verifier};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
/// let header = json!({ "alg": alg.name() });
/// let claims = json!({ "foo": "bar" });
/// let token = jwt::encode(&header, &claims, &alg)?;
/// # Ok(())
/// # }
/// ```
///
/// Or to encode and sign a token with an RSA private key:
/// ```rust
/// # use serde_json::json;
/// # use serde_json::value::Value;
/// # use jsonwebtokens as jwt;
/// # use jwt::{Algorithm, AlgorithmID, Verifier};
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let pem_data = include_bytes!("../tests/rsa/private_rsa_key_pkcs1.pem");
/// let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
/// let header = json!({ "alg": alg.name() });
/// let claims = json!({ "foo": "bar" });
/// let token = jwt::encode(&header, &claims, &alg)?;
/// # Ok(())
/// # }
/// ```
pub fn encode<H: Serialize, C: Serialize>(
    header: &H,
    claims: &C,
    algorithm: &Algorithm,
) -> Result<String, Error> {
    let encoded_header = b64_encode_part(&header)?;
    let encoded_claims = b64_encode_part(&claims)?;
    let message = [encoded_header.as_ref(), encoded_claims.as_ref()].join(".");
    let signature = algorithm.sign(&message)?;
    Ok([message, signature].join("."))
}
