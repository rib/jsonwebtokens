use tokio;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::value::Value;

use jwt_rust as jwt;
use jwt::Verifier;
use jwt::crypto::{Algorithm, AlgorithmID};

mod common;
use common::get_time;

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
        .with_audience("test")
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
        .with_audience("test")
        .claim_equals("my_claim", "food")
        .build().unwrap();
    let _claims: Value = verifier.verify(&token_str, &alg).await.unwrap();
}