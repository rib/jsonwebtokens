use serde_json::json;
use serde_json::value::Value;

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, TokenData, Verifier};

use crate::common::get_time;

const RSA_ALGORITHMS: &[AlgorithmID] = &[
    AlgorithmID::RS256,
    AlgorithmID::RS384,
    AlgorithmID::RS512,
    AlgorithmID::PS256,
    AlgorithmID::PS384,
    AlgorithmID::PS512,
];

#[test]
#[should_panic(expected = "AlgorithmMismatch")]
fn decode_token_wrong_algorithm() {
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pubkey_pem).unwrap();
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.I1BvFoHe94AFf09O6tDbcSB8-jp8w6xZqmyHIwPeSdY";
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &alg).unwrap();
}

#[test]
fn round_trip_sign_verification_pem_pkcs1() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();
        let signature = alg.sign("hello world").unwrap();
        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        alg.verify(None, "hello world", signature).unwrap();
    }
}

#[test]
fn round_trip_sign_verification_certificate_pem() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let certificate = include_bytes!("certificate_rsa_pkcs1.crt");

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();
        let signature = alg.sign("hello world").unwrap();
        let alg = Algorithm::new_rsa_pem_verifier(id, certificate).unwrap();
        alg.verify(None, "hello world", signature).unwrap();
    }
}

#[test]
fn round_trip_sign_verification_pem_pkcs8() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs8.pem");

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();
        let signature = alg.sign("hello world").unwrap();
        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        alg.verify(None, "hello world", signature).unwrap();
    }
}

#[test]
fn round_trip_claims() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs8.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs8.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();

        let header = json!({"alg": alg.name(), "my_hdr": "my_hdr_val"});
        let token = jwt::encode(&header, &my_claims, &alg).unwrap();

        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        let verifier = Verifier::create().build().unwrap();
        let claims: Value = verifier.verify(token, &alg).unwrap();

        assert_eq!(my_claims, claims);
    }
}

#[test]
fn round_trip_claims_and_custom_header() {
    let privkey_pem = include_bytes!("private_rsa_key_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_pkcs1.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();

        let header = json!({"alg": alg.name(), "kid": "kid1234", "my_hdr": "my_hdr_val"});
        let token = jwt::encode(&header, &my_claims, &alg).unwrap();

        let mut alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        alg.set_kid("kid1234");
        let verifier = Verifier::create().build().unwrap();

        // We have to use the lower-level for_time API if we want to see the header
        let TokenData { header, claims, .. } =
            verifier.verify_for_time(token, &alg, get_time()).unwrap();

        assert_eq!(my_claims, claims);
        assert_eq!(header.get("kid").unwrap(), "kid1234");
        assert_eq!(header.get("my_hdr").unwrap(), "my_hdr_val");
    }
}

#[test]
#[should_panic(expected = "InvalidInput")]
fn dont_allow_sign_with_verify_algorithm() {
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let keypair = include_bytes!("private_rsa_key_pkcs1.pem");

    let verify_alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, keypair).unwrap();

    let header = json!({"alg": verify_alg.name()});
    let _token = jwt::encode(&header, &my_claims, &verify_alg).unwrap();
}

#[test]
#[should_panic(expected = "InvalidInput")]
fn dont_allow_verify_with_sign_algorithm() {
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let keypair = include_bytes!("private_rsa_key_pkcs1.pem");

    let sign_alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, keypair).unwrap();

    let header = json!({"alg": sign_alg.name()});
    let token = jwt::encode(&header, &my_claims, &sign_alg).unwrap();

    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &sign_alg).unwrap();
}

#[test]
fn rsa_modulus_exponent() {
    let privkey = include_bytes!("private_rsa_key_pkcs1.pem");
    let sign_alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, privkey).unwrap();
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let n = "yRE6rHuNR0QbHO3H3Kt2pOKGVhQqGZXInOduQNxXzuKlvQTLUTv4l4sggh5_CYYi_cvI-SXVT9kPWSKXxJXBXd_4LkvcPuUakBoAkfh-eiFVMh2VrUyWyj3MFl0HTVF9KwRXLAcwkREiS3npThHRyIxuy0ZMeZfxVL5arMhw1SRELB8HoGfG_AtH89BIE9jDBHZ9dLelK9a184zAf8LwoPLxvJb3Il5nncqPcSfKDDodMFBIMc4lQzDKL5gvmiXLXB1AGLm8KBjfE8s3L5xqi-yUod-j8MtvIj812dkS4QMiRVN_by2h3ZY8LYVGrqZXZTcgn2ujn8uKjXLZVD5TdQ";
    let e = "AQAB";

    let header = json!({"alg": sign_alg.name() });
    let token = jwt::encode(&header, &my_claims, &sign_alg).unwrap();

    let verify_alg = Algorithm::new_rsa_n_e_b64_verifier(AlgorithmID::RS256, n, e).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &verify_alg).unwrap();
}

// https://jwt.io/ is often used for examples so ensure their example works with jsonwebtoken
#[test]
fn roundtrip_with_jwtio_example_jey() {
    let privkey_pem = include_bytes!("private_rsa_key_jwtio_pkcs1.pem");
    let pubkey_pem = include_bytes!("public_rsa_key_jwtio_pkcs1.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for &id in RSA_ALGORITHMS {
        let alg = Algorithm::new_rsa_pem_signer(id, privkey_pem).unwrap();

        let header = json!({"alg": alg.name()});
        let token = jwt::encode(&header, &my_claims, &alg).unwrap();

        let alg = Algorithm::new_rsa_pem_verifier(id, pubkey_pem).unwrap();
        let verifier = Verifier::create().build().unwrap();
        let claims: Value = verifier.verify(token, &alg).unwrap();

        assert_eq!(my_claims, claims);
    }
}
