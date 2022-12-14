use tokio_test::*;

use serde_json::json;
use serde_json::value::Value;

use jsonwebtokens as jwt;
use jwt::raw::TokenSlices;
use jwt::{raw, Algorithm, AlgorithmID, TokenData, Verifier};

mod common;
use common::get_time;

#[test]
fn sign_hs256() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let result = alg.sign("hello world").unwrap();
    let expected = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    assert_eq!(result, expected);
}

#[test]
fn verify_hs256() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    assert_ok!(alg.verify(None, "hello world", sig));
}

#[test]
fn verify_hs256_signature_only() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let TokenSlices {
        message,
        signature,
        header,
        ..
    } = raw::split_token(&token_str).unwrap();
    let header = raw::decode_json_token_slice(header).unwrap();

    assert_ok!(raw::verify_signature_only(
        &header, message, signature, &alg
    ));
}

#[test]
#[should_panic(expected = "InvalidSignature")]
fn hmac_256_bad_secret() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "wrong-secret").unwrap();
    let validator = Verifier::create().build().unwrap();
    let _claims: Value = validator.verify(token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "AlgorithmMismatch")]
fn missing_alg() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();

    let header = json!({});
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let validator = Verifier::create().build().unwrap();
    let _claims: Value = validator.verify(token_str, &alg).unwrap();
}

#[test]
fn round_trip_claims() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let header = json!({"alg": "HS256"});
    let token = jwt::encode(&header, &my_claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();
    let claims: Value = verifier.verify(token, &alg).unwrap();

    assert_eq!(my_claims, claims);
}

#[test]
fn round_trip_claims_and_custom_header() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let header = json!({"alg": "HS256", "my_hdr": "my_hdr_val"});
    let token = jwt::encode(&header, &my_claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();

    // We have to use the lower-level for_time API if we want to see the header
    let TokenData { header, claims, .. } =
        verifier.verify_for_time(token, &alg, get_time()).unwrap();

    assert_eq!(my_claims, claims);
    assert_eq!(header.get("my_hdr").unwrap(), "my_hdr_val");
}

#[test]
fn round_trip_claims_and_kid() {
    let mut alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    alg.set_kid("kid1234");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let header = json!({
        "alg": alg.name(),
        "kid": alg.kid(),
        "my_hdr": "my_hdr_val"
    });
    let token = jwt::encode(&header, &my_claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();

    // We have to use the lower-level for_time API if we want to see the header
    let TokenData { header, claims, .. } =
        verifier.verify_for_time(token, &alg, get_time()).unwrap();

    assert_eq!(my_claims, claims);
    assert_eq!(header.get("kid").unwrap(), "kid1234");
    assert_eq!(header.get("my_hdr").unwrap(), "my_hdr_val");
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn round_trip_claims_and_wrong_kid() {
    let mut alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    alg.set_kid("kid1234");

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let header = json!({
        "alg": alg.name(),
        "kid": "kid4321",
        "my_hdr": "my_hdr_val"
    });
    let token = jwt::encode(&header, &my_claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();

    // We have to use the lower-level for_time API if we want to see the header
    let TokenData { header, claims, .. } =
        verifier.verify_for_time(token, &alg, get_time()).unwrap();

    assert_eq!(my_claims, claims);
    assert_eq!(header.get("kid").unwrap(), "kid1234");
    assert_eq!(header.get("my_hdr").unwrap(), "my_hdr_val");
}

#[test]
fn decode_token() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";

    let verifier = Verifier::create().build().unwrap();
    let claims: Value = verifier.verify(token, &alg).unwrap();
    println!("{claims:?}");
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn decode_token_missing_parts() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &alg).unwrap();
}

#[test]
#[should_panic(expected = "InvalidSignature")]
fn decode_token_invalid_signature() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let token =
        "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUifQ.wrong";
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &alg).unwrap();
}

#[test]
fn decode_token_with_bytes_secret() {
    let secret_b64 = base64::encode_config(b"\x01\x02\x03", base64::URL_SAFE_NO_PAD);
    let alg = Algorithm::new_hmac_b64(AlgorithmID::HS256, secret_b64).unwrap();
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.Hm0yvKH25TavFPz7J_coST9lZFYH1hQo0tvhvImmaks";
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(token, &alg).unwrap();
}

#[test]
fn only_decode_token_header() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.S";
    let header = raw::decode_header_only(token).unwrap();
    assert_eq!(header.get("alg").expect("missing alg"), "HS256");
    assert_eq!(header.get("typ").expect("missing typ"), "JWT");
}

#[test]
fn only_decode_token_header_with_slice_api() {
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJjb21wYW55IjoiMTIzNDU2Nzg5MCIsInN1YiI6IkpvaG4gRG9lIn0.S";
    let TokenSlices { header, .. } = raw::split_token(token).unwrap();
    let header = raw::decode_json_token_slice(header).unwrap();
    assert_eq!(header.get("alg").expect("missing alg"), "HS256");
    assert_eq!(header.get("typ").expect("missing typ"), "JWT");
}

#[test]
fn only_decode_token() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.9r56oF7ZliOBlOAyiOFperTGxBtPykRQiWNFxhDCW98";
    let TokenData { header, claims, .. } = raw::decode_only(token).unwrap();

    assert_eq!(header.get("alg").expect("missing alg"), "HS256");
    assert_eq!(header.get("typ").expect("missing typ"), "JWT");
    assert_eq!(claims.get("sub").expect("no sub"), "b@b.com");
    assert_eq!(claims.get("company").expect("no company"), "ACME");
    assert_eq!(claims.get("exp").expect("no exp"), 2532524891u64);
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn split_token_missing_parts() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
    let _token_slices = raw::split_token(token).unwrap();
}

#[test]
fn only_decode_token_invalid_signature() {
    let token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.wrong";
    let _token_data = raw::decode_only(token).unwrap();
}

#[test]
fn only_decode_token_wrong_algorithm() {
    let token = "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJiQGIuY29tIiwiY29tcGFueSI6IkFDTUUiLCJleHAiOjI1MzI1MjQ4OTF9.fLxey-hxAKX5rNHHIx1_Ch0KmrbiuoakDVbsJjLWrx8fbjKjrPuWMYEJzTU3SBnYgnZokC-wqSdqckXUOunC-g";
    let _token_data = raw::decode_only(token).unwrap();
}
