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

#[test]
fn decode_test_issue_3() {
    // https://github.com/rib/jsonwebtokens-cognito/issues/3
    let token = "eyJraWQiOiJRVGp3dnFlYktUM0swbVdhK3B6aGxYQWRpS3VTMW94XC9hRTh2RkVEd1EyVT0iLCJhbGciOiJSUzI1NiJ9.eyJhdF9oYXNoIjoiZW1JOUh0SDVDbUNMQ0lLTHhPZXpRUSIsInN1YiI6Ijg1Mjc1YjI1LTFmOGUtNDAyZi04MzNjLTg3YmNkODlkNjljZSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJpc3MiOiJodHRwczpcL1wvY29nbml0by1pZHAudXMtZWFzdC0yLmFtYXpvbmF3cy5jb21cL3VzLWVhc3QtMl9WMlZ0WFlPVzAiLCJjb2duaXRvOnVzZXJuYW1lIjoic2hyYXZhbiIsIm9yaWdpbl9qdGkiOiIwMjQwMDU0YS0wYjBkLTQ1ZWUtODg5NS02ZmJjMGM5ZTM3MGEiLCJhdWQiOiI3ZGNudTZocmJmYmFzbjAycmpiMHRvb3A5dCIsImV2ZW50X2lkIjoiYzhhYzY0M2MtZmM2Ny00YmYyLTg2NmItNzBkNTYyZmQ4OWFlIiwidG9rZW5fdXNlIjoiaWQiLCJhdXRoX3RpbWUiOjE2NzgwMjA2NDcsImV4cCI6MTY3ODAyNDI0NywiaWF0IjoxNjc4MDIwNjQ3LCJqdGkiOiI5ZWU5OTc2OS00YWZhLTQ0MjAtOTcwZC0zZmU4NWRmM2ExYmYiLCJlbWFpbCI6InNocmF2YW5zaGV0dHkzMjJAZ21haWwuY29tIn0.aFySCAAjFsv6MBH7uPfTM4RC2yNghFgjyBvumRhz4TRJkXzVPpzOaV2IXK1CWhQLluSEeQhZADaun8nc7wuFF-xezO2GHFqeU1bVUQO8YUXtAHP3CXH7eC4UKS1QAyXBNQWKGuwLUCnfkWBaqnJrk6lmmqhprXZy6TkdRSeDuf3XzHTndZPLNRMmYuwG1mp7BY1Y7bPpalC-cMA-la4O__mL3TeeSeIXwouxYMTc8fxRHUrAKzXyKitLjdIFl3qG0oJ7La_e2YulaAb5l4RcLS1W1tmUNYUoXP8DNOZA7tP5n6glSj1WF2xhxjyNuE5vtyrP9JJV-zMI97K_F1QUyw";

    // public key from https://cognito-idp.us-east-2.amazonaws.com/us-east-2_V2VtXYOW0/.well-known/jwks.json
    /*
    {
        "alg":"RS256",
        "e":"AQAB",
        "kid":"QTjwvqebKT3K0mWa+pzhlXAdiKuS1ox/aE8vFEDwQ2U="
        "kty":"RSA",
        "n":"oGLoW1un7726NaGmKomyQydPjSMClNSLC9Nh0V0ch8O76sBiDm5vMPy6i8NPXV7T9dENtvBC3dv7SWX9PxVuxfCoer8x9645ufYQqtML520kmTqIbW6CB6m5F56tC_xu9VVovRYdqzDINxrplMsexm4m0FUxKypHcVpZpDCeB8GK1ssnVLrQ7LRbhwxne0keeXcM0OtqNMSS0PwvVGlOzzrJLID8p_IUYNkDThSKFZRjBNd606OmplEIYNgklS2wVMoBnR0yT95N9TQ3672NTz2wYl9g1x1kgKfQVNZsybprh6g9ZuuYvWtkP7HFq8veNUQ-0IuUSVS-sYj4mWf9bQ",
        "use":"sig"
    },
    {
        "alg":"RS256",
        "e":"AQAB",
        "kid":"PfPSfsL2IiAcScj/gUx4waEjMiqPGSHI27SdH94NHJE=",
        "kty":"RSA",
        "n":"mA_5EPWdcDANel6fAjz-9nHDOVC0WDD88xsJ_-nZpA6O_goce8Np1CvBIV8aZxropffUcg2ySUZ6cpcdm1lw0t7dAhyZyEO0POo3uyy4mrLx4H_50lRWOmg8ZPC6JhEDC-p1R-8kIYXqpmTzAMkGxtjxCbbs0gg4huvmfWNrYDkaNHiDRjJ38kr_zG-Pb6hNl4ynRN1-GXtkdLlGLmoW3oHy95QKwBTUVdmBjZZIXlS7rOOJ8RHI4xVKrgwsopNifA75g7izvTyEEJsQ1ofv0ROJCWPyXZHExDwRB3GxhiyR6noULygNZu-_zWPAyRbSEw1GWSZIuhBaxiXF9InSVw",
        "use":"sig"
    }
    */
    let n = "oGLoW1un7726NaGmKomyQydPjSMClNSLC9Nh0V0ch8O76sBiDm5vMPy6i8NPXV7T9dENtvBC3dv7SWX9PxVuxfCoer8x9645ufYQqtML520kmTqIbW6CB6m5F56tC_xu9VVovRYdqzDINxrplMsexm4m0FUxKypHcVpZpDCeB8GK1ssnVLrQ7LRbhwxne0keeXcM0OtqNMSS0PwvVGlOzzrJLID8p_IUYNkDThSKFZRjBNd606OmplEIYNgklS2wVMoBnR0yT95N9TQ3672NTz2wYl9g1x1kgKfQVNZsybprh6g9ZuuYvWtkP7HFq8veNUQ-0IuUSVS-sYj4mWf9bQ";
    let e = "AQAB";

    let alg = Algorithm::new_rsa_n_e_b64_verifier(AlgorithmID::RS256, n, e).unwrap();
    let verifier = Verifier::create().build().unwrap();

    let jwt::raw::TokenSlices {message, signature, header, claims } = jwt::raw::split_token(token).unwrap();
    let header = jwt::raw::decode_json_token_slice(header).unwrap();
    jwt::raw::verify_signature_only(&header, message, signature, &alg).unwrap();
    let claims = jwt::raw::decode_json_token_slice(claims).unwrap();
    verifier.verify_claims_only(&claims, 1678020647).unwrap();
}
