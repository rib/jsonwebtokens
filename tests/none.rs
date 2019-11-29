use tokio_test::*;
use tokio;
use serde_json::json;
use serde_json::value::Value;

use jwt_rust as jwt;
use jwt::{Verifier};
use jwt::crypto::{Algorithm, AlgorithmID};

mod common;
use common::get_time;

#[test]
fn jwt_name() {
    let alg = Algorithm::new_unsecured().unwrap();
    assert_eq!(alg.get_jwt_name(), "none");
}

#[tokio::test]
async fn sign_none() {
    let alg = Algorithm::new_unsecured().unwrap();
    let result = alg.sign(None, "hello world").await.unwrap();
    assert_eq!(result, "");
}

#[tokio::test]
async fn verify_none() {
    let alg = Algorithm::new_unsecured().unwrap();
    assert_ok!(alg.verify(None, "hello world", "").await);
}

#[tokio::test]
#[should_panic(expected = "InvalidSignature")]
async fn verify_none_with_non_empty_signature() {
    let alg = Algorithm::new_unsecured().unwrap();
    let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    let _claims = alg.verify(None, "hello world", sig).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "AlgorithmMismatch")]
async fn missing_alg() {
    let alg = Algorithm::new_unsecured().unwrap();
    let header = json!({ });
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();

    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let validator = Verifier::create().build().unwrap();
    let _claims: Value = validator.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
#[should_panic(expected = "AlgorithmMismatch")]
async fn wrong_alg() {
    let alg = Algorithm::new_unsecured().unwrap();

    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(None, &header, &claims, &alg).await.unwrap();

    let validator = Verifier::create().build().unwrap();
    let _claims: Value = validator.verify(&token_str, &alg).await.unwrap();
}

#[tokio::test]
async fn round_trip_claims() {
    let alg = Algorithm::new_unsecured().unwrap();

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let header = json!({"alg": alg.get_jwt_name()});
    let token = jwt::encode(None, &header, &my_claims, &alg).await.unwrap();

    let verifier = Verifier::create().build().unwrap();
    let claims: Value = verifier.verify(token, &alg).await.unwrap();

    assert_eq!(my_claims, claims);
}

#[tokio::test]
async fn no_trailing_dot() {
    let alg = Algorithm::new_unsecured().unwrap();

    let token_ok   = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ.";
    let token_bad  = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ";

    let verifier = Verifier::create().build().unwrap();
    let result: Result<Value, jwt::error::Error> = verifier.verify(token_ok, &alg).await;
    assert_ok!(result);

    let result: Result<Value, jwt::error::Error> = verifier.verify(token_bad, &alg).await;
    assert_err!(result);
}

#[tokio::test]
async fn token_with_non_empty_signature() {
    let alg = Algorithm::new_unsecured().unwrap();

    let token_ok   = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ.";
    let token_bad  = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ.1234";

    let verifier = Verifier::create().build().unwrap();
    let result: Result<Value, jwt::error::Error> = verifier.verify(token_ok, &alg).await;
    assert_ok!(result);

    let result: Result<Value, jwt::error::Error> = verifier.verify(token_bad, &alg).await;
    assert_err!(result);
}