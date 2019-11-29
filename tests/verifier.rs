use tokio;
use serde_json::json;
use serde_json::value::Value;

use jwt_rust as jwt;
use jwt::Verifier;
use jwt::crypto::{Algorithm, AlgorithmID};

mod common;
use common::get_time;

const REFERENCE_TIME: u64 = 1575057015u64;

#[tokio::test]
async fn verify_custom_claim() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
        "my_claim": "foo"
    });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_equals("my_claim", "foo")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn bad_custom_claim() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
        "my_claim": "foo"
    });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_equals("my_claim", "food")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn non_integer_iat() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iat": "1575057015" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn non_integer_exp() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "exp": "1575057015" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn non_integer_nbf() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "nbf": "1575057015" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn non_string_iss() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": 1234 });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn non_string_aud() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": 1234 });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn non_string_sub() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "sub": 1234 });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
async fn iss_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": "ACME" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create()
        .issuer("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn iss_not_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": "ACMEv2" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create()
        .issuer("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
async fn aud_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "ACME" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create()
        .audience("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn aud_not_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "ACMEv2" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create()
        .audience("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
async fn sub_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "sub": "ACME" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create()
        .subject("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "MalformedToken")]
async fn sub_not_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "sub": "ACMEv2" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();
    let verifier = Verifier::create()
        .subject("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}
