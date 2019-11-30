
A Rust implementation of [Json Web Tokens](https://tools.ietf.org/html/rfc7519)

# Installation

```
jwt-rust = "1"
serde_json = "1"
```

# Usage

The main two types are `Algorithm` which encapsulates a chosen cryptographic
function for signing or verifying tokens, and a `Verifier` that gives a
flexible way of describing how incoming tokens should be checked.

Creating an `Algorithm` up front means we don't have to repeatedly parse
associated secrets or keys.

A builder pattern is used for describing verifiers so it should be possible
to extend its configurability if necessary for different use cases.

## Signing a token

with a symmetric secret:
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
let header = json!({ "alg": alg.get_jwt_name() });
let claims = json!({ "foo": "bar" });
let token = encode(&header, &claims, &alg).unwrap();
```
or if the secret isn't a string pass it base64 encoded:
```rust
let alg = Algorithm::new_hmac_b64(AlgorithmID::HS256, secret_data).unwrap();
```

with an RSA private key:
```rust
let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data).unwrap();
let header = json!({ "alg": alg.get_jwt_name() });
let claims = json!({ "foo": "bar" });
let token = encode(&header, &claims, &alg).unwrap();
```

## Verifying tokens

with a symmetric secret:
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
let verifier = Verifier::create()
    .issuer("http://some-auth-service.com")
    .audience("application_id")
    .build().unwrap();
let claims: Value = verifier.verify(&token_str, &alg).unwrap();
```

with an RSA private key:
```rust
let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pem_data).unwrap();
let verifier = Verifier::create()
    .issuer("http://some-auth-service.com")
    .audience("application_id")
    .build().unwrap();
let claims: Value = verifier.verify(&token_str, &alg).unwrap();
```

## Verifying standard claims
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
let verifier = Verifier::create()
    .issuer("http://some-auth-service.com")
    .audience("application_id")
    .subject("subject")
    .nonce("9837459873945093845")
    .leeway(5) // give this much leeway (in seconds) when validating exp, nbf and iat claims
    .build().unwrap();
let claims: Value = verifier.verify(&token_str, &alg).unwrap();
```

## Verifying custom claims
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
let verifier = Verifier::create()
    .claim_equals("my_claim0", "value")
    .claim_matches("my_claim1", "value[0-9]")
    .claim_equals_one_of("my_claim2", &["value0", "value1"])
    .claim_matches_one_of("my_claim3", &[regex0, regex1])
    .build().unwrap();
let claims: Value = verifier.verify(&token_str, &alg).unwrap();
```

## Verifying timestamps (or not)
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret").unwrap();
let verifier = Verifier::create()
    .leeway(5)    // give this much leeway when validating exp, nbf and iat claims
    .ignore_exp() // ignore expiry
    .ignore_nbf() // ignore 'not before time'
    .ignore_iat() // ignore issue time
    .build().unwrap();
let claims: Value = verifier.verify(&token_str, &alg).unwrap();
```

## Just parse the header
```rust
let header = decode_header_only(token);
let kid = match header.get("kid") {
    Some(Value::String(s)) => s,
    _ => return Err(())
};
```


# Algorithms Supported

Array of supported algorithms. The following algorithms are currently supported.

alg Parameter Value | Digital Signature or MAC Algorithm
----------------|----------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
RS384 | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
RS512 | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
PS256 | RSASSA-PSS using SHA-256 hash algorithm
PS384 | RSASSA-PSS using SHA-384 hash algorithm
PS512 | RSASSA-PSS using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm (only PKCS#8 format PEM)
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm (only PKCS#8 format PEM)
none | No digital signature or MAC value included
