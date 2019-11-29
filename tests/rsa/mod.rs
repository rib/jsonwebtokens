use tokio;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::value::Value;

use jwt_rust as jwt;
use jwt::Verifier;
use jwt::crypto::{Algorithm, AlgorithmID};

use crate::common::get_time;

const RSA_ALGORITHMS: &[AlgorithmID] = &[
    AlgorithmID::RS256,
    AlgorithmID::RS384,
    AlgorithmID::RS512,
    AlgorithmID::PS256,
    AlgorithmID::PS384,
    AlgorithmID::PS512,
];

#[tokio::test]
#[should_panic(expected = "AlgorithmMismatch")]
async fn decode_token_wrong_algorithm() {
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pubkey_pem).unwrap();
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &alg).await.unwrap();
}

#[tokio::test]
async fn round_trip_sign_verification_pem_pkcs1() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();
        let signature = alg.sign(None, "hello world").await.unwrap();
        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        alg.verify(None, "hello world", signature).await.unwrap();
    }
}

#[tokio::test]
async fn round_trip_sign_verification_pem_pkcs8() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs8.pem");

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();
        let signature = alg.sign(None, "hello world").await.unwrap();
        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        alg.verify(None, "hello world", signature).await.unwrap();
    }
}

#[tokio::test]
async fn round_trip_claims() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs8.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();

        let header = json!({"alg": alg.get_jwt_name(), "kid": "kid", "my_hdr": "my_hdr_val"});
        let token = jwt::encode(Some("kid"), &header, &my_claims, &alg).await.unwrap();

        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        let verifier = Verifier::create().build().unwrap();
        let claims: Value = verifier.verify(token, &alg).await.unwrap();

        assert_eq!(my_claims, claims);
    }
}

#[tokio::test]
async fn round_trip_claims_and_custom_header() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();

        let header = json!({"alg": alg.get_jwt_name(), "kid": "kid", "my_hdr": "my_hdr_val"});
        let token = jwt::encode(Some("kid"), &header, &my_claims, &alg).await.unwrap();

        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        let verifier = Verifier::create().build().unwrap();

        // We have to use the lower-level for_time API if we want to see the header
        let token_data = verifier.verify_for_time(token, &alg, get_time()).await.unwrap();

        // The returned claims are just the Map which is probably more likely to be
        // convenient in practice, but here we have to convert it into a
        // serde_json::value::Value to compare with the original claims
        let verified_claims = Value::Object(token_data.claims.expect("no claims"));

        assert_eq!(my_claims, verified_claims);
        assert_eq!(token_data.header.get("kid").unwrap(), "kid");
        assert_eq!(token_data.header.get("my_hdr").unwrap(), "my_hdr_val");
    }
}

#[tokio::test]
#[should_panic(expected = "InvalidInput")]
async fn dont_allow_sign_with_verify_algorithm() {
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let keypair = include_bytes!("private_rsa_key_pkcs1.pem");

    let verify_alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, keypair).unwrap();

    let header = json!({"alg": verify_alg.get_jwt_name(), "kid": "kid"});
    let _token = jwt::encode(Some("kid"), &header, &my_claims, &verify_alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "InvalidInput")]
async fn dont_allow_verify_with_sign_algorithm() {
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let keypair = include_bytes!("private_rsa_key_pkcs1.pem");

    let sign_alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, keypair).unwrap();

    let header = json!({"alg": sign_alg.get_jwt_name(), "kid": "kid"});
    let token = jwt::encode(Some("kid"), &header, &my_claims, &sign_alg).await.unwrap();

    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &sign_alg).await.unwrap();
}

#[tokio::test]
async fn rsa_modulus_exponent() {
    let privkey = include_bytes!("private_rsa_key_pkcs1.pem");
    let sign_alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, privkey).unwrap();
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let n = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
    let e = "AQAB";

    let header = json!({"alg": sign_alg.get_jwt_name() });
    let token = jwt::encode(None, &header, &my_claims, &sign_alg).await.unwrap();

    let verify_alg = Algorithm::new_rsa_n_e_b64_verifier(AlgorithmID::RS256, n, e).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &verify_alg).await.unwrap();
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[tokio::test]
async fn roundtrip_with_jwtio_example_jey() {
    let privkey_pem = include_bytes!("private_rsa_key_jwtio_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_jwtio_pkcs1.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();

        let header = json!({"alg": alg.get_jwt_name()});
        let token = jwt::encode(None, &header, &my_claims, &alg).await.unwrap();

        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        let verifier = Verifier::create().build().unwrap();
        let claims: Value = verifier.verify(token, &alg).await.unwrap();

        assert_eq!(my_claims, claims);
    }
}
