use jsonwebtokens as jwt;
use jwt::{encode, Algorithm, AlgorithmID, Verifier};
use serde_json::{json, Value};
use std::{
    convert::TryInto,
    time::{SystemTime, UNIX_EPOCH},
};

fn sign(payload: Value, private_key: &str, algorithm_id: AlgorithmID) -> String {
    let alg = Algorithm::new_hmac(algorithm_id, private_key).expect("alg error");
    let header = json!({ "alg": alg.name() });
    let claims = payload;

    let token = encode(&header, &claims, &alg).expect("encode error");
    return token;
}

fn verify(token_str: &str) -> Value {
    let verifier = Verifier::create().build().unwrap();
    let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").expect("error while alg");
    let decoded_token = verifier
        .verify(&token_str, &alg)
        .expect("error while decoding");
    return decoded_token;
}

fn main() {
    let now: u64 = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .try_into()
        .unwrap(); // timestamp for now
    let exp: u64 = (now + 3 * 60 * 60).try_into().unwrap(); // 3 hours
    let iat: u64 = now;

    let payload = json!({
        "iat": iat,
        "name": "yusufkaraca",
        "password": "123",
        "exp": exp
    });

    let token = sign(payload, "secret", AlgorithmID::HS256);
    println!("token is => {}", token);

    let decoded_json: Value = verify(&token);
    println!("decoded json is => {}", decoded_json)
}
