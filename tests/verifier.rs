use serde_json::json;
use serde_json::value::Value;
use regex::Regex;

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, Verifier};

mod common;
use common::get_time;

#[test]
fn claim_equals() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
        "my_claim": "foo"
    });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_equals("my_claim", "foo")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn claim_equals_failure() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
        "my_claim": "foo"
    });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_equals("my_claim", "food")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn claim_equals_missing() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
    });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_equals("my_claim", "foo")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
fn claim_matches() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
        "my_claim": "foo"
    });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_matches("my_claim", Regex::new("[fo]+").unwrap())
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn claim_matches_failure() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
        "my_claim": "foo"
    });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_matches("my_claim", Regex::new("[bar]+").unwrap())
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn claim_matches_missing() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({
        "aud": "test",
        "exp": get_time() + 10000,
    });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create()
        .audience("test")
        .claim_matches("my_claim", Regex::new("[bar]+").unwrap())
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn claim_equals_wrong_type() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "my_claim": 1234 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_equals("my_claim", "1234")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn non_integer_iat() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iat": "1575057015" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn non_integer_exp() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "exp": "1575057015" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn non_integer_nbf() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "nbf": "1575057015" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn non_string_iss() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": 1234 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn non_string_aud() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": 1234 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn non_string_sub() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "sub": 1234 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create().build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
fn iss_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": "ACME" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .issuer("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn iss_not_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": "ACMEv2" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .issuer("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
fn aud_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "ACME" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .audience("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn aud_not_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "aud": "ACMEv2" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .audience("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
fn sub_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "sub": "ACME" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .subject("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn sub_not_equal() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "sub": "ACMEv2" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .subject("ACME")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
fn equals_one_of() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "my_claim": "value0" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_equals_one_of("my_claim", &["value0", "value1"])
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn equals_one_of_failure() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "my_claim": "value0" });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_equals_one_of("my_claim", &["value1", "value2"])
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn equals_one_of_wrong_type() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "my_claim": 1234 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_equals_one_of("my_claim", &["1234"])
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).unwrap();
}

#[test]
fn matches_one_of() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims0 = json!({ "my_claim": "value0" });
    let token0 = jwt::encode(&header, &claims0, &alg).unwrap();
    let claims1 = json!({ "my_claim": "other3" });
    let token1 = jwt::encode(&header, &claims1, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_matches_one_of("my_claim",
            &[Regex::new("value[0123]").unwrap(),
              Regex::new("other[0123]").unwrap()])
        .build().unwrap();
    let _claims0: Value = verifier.verify(&token0, &alg).unwrap();
    let _claims1: Value = verifier.verify(&token1, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn matches_one_of_failure() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "my_claim": "value4" });
    let token = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_matches_one_of("my_claim",
            &[Regex::new("value[0123]").unwrap(),
              Regex::new("other[0123]").unwrap()])
        .build().unwrap();
    let _claims: Value = verifier.verify(&token, &alg).unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn matches_one_of_missing() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iss": "ACME" });
    let token = jwt::encode(&header, &claims, &alg).unwrap();
    let verifier = Verifier::create()
        .claim_matches_one_of("my_claim",
            &[Regex::new("value[0123]").unwrap(),
              Regex::new("other[0123]").unwrap()])
        .build().unwrap();
    let _claims: Value = verifier.verify(&token, &alg).unwrap();
}