use serde_json::json;
use serde_json::value::Value;

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, Verifier};

use crate::common::get_time;

struct KeyPair<'a> {
    id: AlgorithmID,
    privkey: &'a [u8],
    pubkey: &'a [u8],
}

const EC_ALGORITHMS: &[KeyPair] = &[
    KeyPair {
        id: AlgorithmID::ES256,
        privkey: include_bytes!("private_ecdsa_key_jwtio_p256_pkcs8.pem"),
        pubkey: include_bytes!("public_ecdsa_key_jwtio_p256_pkcs8.pem"),
    },
    KeyPair {
        id: AlgorithmID::ES384,
        privkey: include_bytes!("private_ecdsa_key_jwtio_p384_pkcs8.pem"),
        pubkey: include_bytes!("public_ecdsa_key_jwtio_p384_pkcs8.pem"),
    },
];

#[test]
#[should_panic(expected = "InvalidInput")]
fn fails_with_non_ecdsa_pkcs8_key_format() {
    let privkey = include_bytes!("../rsa/private_rsa_key_pkcs1.pem");
    let _alg = Algorithm::new_ecdsa_pem_signer(AlgorithmID::ES256, privkey).unwrap();
}

#[test]
#[should_panic(expected = "InvalidInput")]
fn wrong_ecdsa_curve() {
    let privkey_pem = include_bytes!("private_ecdsa_key_jwtio_p256_pkcs8.pem");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    let alg = Algorithm::new_ecdsa_pem_signer(AlgorithmID::ES384, privkey_pem).unwrap();

    let header = json!({"alg": alg.name(), "my_hdr": "my_hdr_val"});
    let _token = jwt::encode(&header, &my_claims, &alg).unwrap();
}

#[test]
fn round_trip_sign_verification_pem() {
    for keypair in EC_ALGORITHMS {
        let alg = Algorithm::new_ecdsa_pem_signer(keypair.id, keypair.privkey).unwrap();
        let signature = alg.sign("hello world").unwrap();
        let alg = Algorithm::new_ecdsa_pem_verifier(keypair.id, keypair.pubkey).unwrap();
        alg.verify(None, "hello world", signature).unwrap();
    }
}

#[test]
fn round_trip_claims() {
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });

    for keypair in EC_ALGORITHMS {
        let alg = Algorithm::new_ecdsa_pem_signer(keypair.id, keypair.privkey).unwrap();

        let header = json!({"alg": alg.name(), "my_hdr": "my_hdr_val"});
        let token = jwt::encode(&header, &my_claims, &alg).unwrap();

        let alg = Algorithm::new_ecdsa_pem_verifier(keypair.id, keypair.pubkey).unwrap();
        let verifier = Verifier::create().build().unwrap();
        let claims: Value = verifier.verify(token, &alg).unwrap();

        assert_eq!(my_claims, claims);
    }
}
