use serde_json::json;

use jsonwebtokens as jwt;
use jwt::{error::Error, Algorithm, AlgorithmID, Verifier};

mod common;

const REFERENCE_TIME: u64 = 1575057015u64;

#[test]
fn token_just_expired() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "exp": REFERENCE_TIME });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    // "requires that the current date/time MUST be before the expiration
    //  date/time listed in the "exp" claim."
    // So being equal should be considered expired...
    let verifier = Verifier::create().build().unwrap();
    let result = verifier.verify_for_time(token_str, &alg, REFERENCE_TIME);
    match result {
        Err(Error::TokenExpiredAt(at)) => {
            assert_eq!(at, REFERENCE_TIME);
        }
        _ => unreachable!("Token not expired"),
    }
}

#[test]
fn token_expired() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "exp": REFERENCE_TIME });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();
    let result = verifier.verify_for_time(token_str, &alg, REFERENCE_TIME + 100);
    match result {
        Err(Error::TokenExpiredAt(at)) => {
            assert_eq!(at, REFERENCE_TIME);
        }
        _ => unreachable!("Token not expired"),
    }
}

#[test]
fn ignore_token_expired() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "exp": REFERENCE_TIME });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().ignore_exp().build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME + 100)
        .unwrap();
}

#[test]
fn token_recently_expired_with_leeway() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "exp": REFERENCE_TIME });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().leeway(5).build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME + 1)
        .unwrap();
}

#[test]
fn token_used_exactly_at_nbf_time() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "nbf": REFERENCE_TIME });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    // "The "nbf" (not before) claim identifies the time before which the JWT
    //  MUST NOT be accepted for processing.  The processing of the "nbf"
    //  claim requires that the current date/time MUST be after or equal to
    //  the not-before date/time listed in the "nbf" claim."
    //
    let verifier = Verifier::create().build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME)
        .unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn token_used_early() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "nbf": REFERENCE_TIME + 100 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    // "The "nbf" (not before) claim identifies the time before which the JWT
    //  MUST NOT be accepted for processing.  The processing of the "nbf"
    //  claim requires that the current date/time MUST be after or equal to
    //  the not-before date/time listed in the "nbf" claim."
    //
    let verifier = Verifier::create().build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME)
        .unwrap();
}

#[test]
fn ignore_token_used_early() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "nbf": REFERENCE_TIME + 100 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().ignore_nbf().build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME)
        .unwrap();
}

#[test]
fn token_used_slightly_early_with_leeway() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "nbf": REFERENCE_TIME + 1 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().leeway(5).build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME)
        .unwrap();
}

#[test]
#[should_panic(expected = "MalformedToken")]
fn token_used_before_issue() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iat": REFERENCE_TIME + 100 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME)
        .unwrap();
}

#[test]
fn token_used_before_just_before_issue_with_leeway() {
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
    let header = json!({ "alg": "HS256" });
    let claims = json!({ "iat": REFERENCE_TIME + 1 });
    let token_str = jwt::encode(&header, &claims, &alg).unwrap();

    let verifier = Verifier::create().leeway(5).build().unwrap();
    let _token_data = verifier
        .verify_for_time(token_str, &alg, REFERENCE_TIME)
        .unwrap();
}
