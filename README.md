
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

The builder pattern used for describing a `Verifier` keeps code ergonimic no
matter if you have simple or elaborate verification requirements.

There is also a low-level [(`::raw`)](#Low-level-Usage) API available in
case you need more control over splitting, decoding, deserializing and
verifying tokens.

## Signing a token

with a symmetric secret:
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let header = json!({ "alg": alg.get_jwt_name() });
let claims = json!({ "foo": "bar" });
let token = encode(&header, &claims, &alg)?;
```
or if the secret isn't a string pass it base64 encoded:
```rust
let alg = Algorithm::new_hmac_b64(AlgorithmID::HS256, secret_data)?;
```

with an RSA private key:
```rust
let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
let header = json!({ "alg": alg.get_jwt_name() });
let claims = json!({ "foo": "bar" });
let token = encode(&header, &claims, &alg)?;
```

## Verifying tokens

with a symmetric secret:
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let verifier = Verifier::create()
    .issuer("http://some-auth-service.com")
    .audience("application_id")
    .build()?;
let claims: Value = verifier.verify(&token_str, &alg)?;
```

with an RSA private key:
```rust
let alg = Algorithm::new_rsa_pem_verifier(AlgorithmID::RS256, pem_data)?;
let verifier = Verifier::create()
    .issuer("http://some-auth-service.com")
    .audience("application_id")
    .build()?;
let claims: Value = verifier.verify(&token_str, &alg)?;
```

## Verifying standard claims
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let verifier = Verifier::create()
    .issuer("http://some-auth-service.com")
    .audience("application_id")
    .subject("subject")
    .nonce("9837459873945093845")
    .leeway(5) // give this much leeway (in seconds) when validating exp, nbf and iat claims
    .build()?;
let claims: Value = verifier.verify(&token_str, &alg)?;
```

## Verifying custom claims
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let verifier = Verifier::create()
    .claim_equals("my_claim0", "value")
    .claim_matches("my_claim1", "value[0-9]")
    .claim_equals_one_of("my_claim2", &["value0", "value1"])
    .claim_matches_one_of("my_claim3", &[regex0, regex1])
    .build()?;
let claims: Value = verifier.verify(&token_str, &alg)?;
```

## Verifying timestamps (or not)
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let verifier = Verifier::create()
    .leeway(5)    // give this much leeway when validating exp, nbf and iat claims
    .ignore_exp() // ignore expiry
    .ignore_nbf() // ignore 'not before time'
    .ignore_iat() // ignore issue time
    .build()?;
let claims: Value = verifier.verify(&token_str, &alg)?;
```

# Low-level Usage

In case you have more particular decoding and/or validation requirements than are
currently handled with the above, high-level APIs, enough of the lower-level
implementation details are exposed to allow you to manually split, decode and
verify a JWT token.


## Just split a token into component parts
```rust
let TokenSlices {message, signature, header, claims } = raw::split_token(token)?;
```

## Just parse the header
```rust
use serde_json::value::Value;
let header: Value = raw::decode_header_only(token);
```

## Base64 decode header or claims and deserialize JSON
Equivalent to `raw::decode_header_only()`:
```rust
let TokenSlices {header, .. } = raw::split_token(token)?;
let header = raw::decode_json_token_slice(header)?;
```

Or, decode and deserialize just the claims:
```rust
let TokenSlices {claims, .. } = raw::split_token(token)?;
let claims = raw::decode_json_token_slice(claims)?;
```

## Manually split, decode and verify a token
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let verifier = Verifier::create()
    // snip
    .build()?;

let TokenSlices {message, signature, header, claims } = raw::split_token(token)?;
let header = raw::decode_json_token_slice(header)?;
raw::verify_signature_only(&header, message, signature, &alg)?;
let claims = raw::decode_json_token_slice(claims)?;
verifier.verify_claims_only(&claims, time_now)?;
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
