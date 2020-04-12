[![jsonwebtokens](https://img.shields.io/crates/v/jsonwebtokens?style=flat-square)](https://crates.io/crates/jsonwebtokens)
![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)
[![Build Status](https://travis-ci.org/rib/jsonwebtokens.svg)](https://travis-ci.org/rib/jsonwebtokens)


A Rust implementation of [Json Web Tokens](https://tools.ietf.org/html/rfc7519)

# Installation

```
jsonwebtokens = "1"
serde_json = "1"
```

Then, in your code:
```rust
use serde_json::json;
use serde_json::value::Value;

use jsonwebtokens as jwt;
use jwt::{Algorithm, AlgorithmID, Verifier};
```

# Usage

The main two types are `Algorithm` and `Verifier`. An `Algorithm` encapsulates
a cryptographic function for signing or verifying tokens, and a `Verifier`
handles checking the signature and claims of a token, given an `Algorithm`.

Creating an `Algorithm` separately ensures any parsing of secrets or keys only
needs to happen once.

The builder pattern used for describing a `Verifier` keeps code ergonimic no
matter if you have simple or elaborate verification requirements.

There is also a low-level [(`::raw`)](#Low-level-Usage) API available in
case you need more control over splitting, decoding, deserializing and
verifying tokens.

## Signing a token

with a symmetric secret:
```rust
let alg = Algorithm::new_hmac(AlgorithmID::HS256, "secret")?;
let header = json!({ "alg": alg.name() });
let claims = json!({ "foo": "bar" });
let token = encode(&header, &claims, &alg)?;
```
or if your secret is base64 encoded:
```rust
let alg = Algorithm::new_hmac_b64(AlgorithmID::HS256, secret_data)?;
```

with an RSA private key:
```rust
let alg = Algorithm::new_rsa_pem_signer(AlgorithmID::RS256, pem_data)?;
let header = json!({ "alg": alg.name() });
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
    .string_equals("my_claim0", "value")
    .string_matches("my_claim1", Regex::new("value[0-9]").unwrap())
    .string_equals_one_of("my_claim2", &["value0", "value1"])
    .string_matches_one_of("my_claim3", &[regex0, regex1])
    .claim_callback("my_claim4", |v| v.is_u64() && v.as_u64().unwrap() == 1234)
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

In case you need even more fine-grained control than is possible with the
above APIs, many of the lower-level details are exposed through the `::raw`
module to allow you to manually split, decode and verify a JWT token.


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

# Based on

Originally this project started as a few small changes to
[jsonwebtoken](https://crates.io/crates/jsonwebtoken) (without an 's'), to
meet the needs I had while building
[jsonwebtokens-cognito](https://crates.io/crates/jsonwebtokens-cognito) but
eventually the design and implementation became substantially different with
the creation of the `Algorithm` API and the customizable `Verifier`
API.

The project borrows design ideas from a variety of pre-existing Json Web
Token libraries. In particular it shamelessly steals ideas from
[node-jsonwebtoken](https://github.com/auth0/node-jsonwebtoken) and
[java-jwt](https://github.com/auth0/java-jwt).
