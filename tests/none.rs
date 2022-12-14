use tokio_test::*;

use serde_json::json;
use serde_json::value::Value;

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, Verifier};

mod common;
use common::get_time;

#[test]
fn jwt_name() {
    let alg = Algorithm::new_unsecured().unwrap();
    assert_eq!(alg.name(), "none");
}

#[test]
fn sign_none() {
    let alg = Algorithm::new_unsecured().unwrap();
    let result = alg.sign("hello world").unwrap();
    assert_eq!(result, "");
}

#[test]
fn verify_none() {
    let alg = Algorithm::new_unsecured().unwrap();
    alg.verify(None, "hello world", "").unwrap();
}

#[test]
#[should_panic(expected = "InvalidSignature")]
fn verify_none_with_non_empty_signature() {
    let alg = Algorithm::new_unsecured().unwrap();
    let sig = "c0zGLzKEFWj0VxWuufTXiRMk5tlI5MbGDAYhzaxIYjo";
    alg.verify(None, "hello world", sig).unwrap();
}

#[test]
#[should_panic(expected = "AlgorithmMismatch")]
fn missing_alg() {
    let alg = Algorithm::new_unsecured().unwrap();
    let header = json!({});
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let validator = Verifier::create().build().unwrap();
    let _claims: Value = validator.verify(token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "AlgorithmMismatch")]
fn wrong_alg() {
    let alg = Algorithm::new_unsecured().unwrap();

    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "test" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let validator = Verifier::create().build().unwrap();
    let _claims: Value = validator.verify(token_str, &alg).unwrap();
}

#[test]
fn round_trip_claims() {
    let alg = Algorithm::new_unsecured().unwrap();

    let my_claims = json!({
        "sub": "b@b.com",
        "company": "ACME",
        "exp": get_time() + 10000,
    });
    let header = json!({"alg": alg.name()});
    let token = jwt::encode(&header, &my_claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();
    let claims: Value = verifier.verify(token, &alg).unwrap();

    assert_eq!(my_claims, claims);
}

#[test]
fn no_trailing_dot() {
    let alg = Algorithm::new_unsecured().unwrap();

    let token_ok = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ.";
    let token_bad = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ";

    let verifier = Verifier::create().build().unwrap();
    let result: Result<Value, jwt::error::Error> = verifier.verify(token_ok, &alg);
    assert_ok!(result);

    let result: Result<Value, jwt::error::Error> = verifier.verify(token_bad, &alg);
    assert_err!(result);
}

#[test]
fn token_with_non_empty_signature() {
    let alg = Algorithm::new_unsecured().unwrap();

    let token_ok = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ.";
    let token_bad = "eyJhbGciOiJub25lIn0.eyJjb21wYW55IjoiQUNNRSIsInN1YiI6ImJAYi5jb20ifQ.1234";

    let verifier = Verifier::create().build().unwrap();
    let result: Result<Value, jwt::error::Error> = verifier.verify(token_ok, &alg);
    assert_ok!(result);

    let result: Result<Value, jwt::error::Error> = verifier.verify(token_bad, &alg);
    assert_err!(result);
}
