use serde_json::value::Value;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::SystemTime;

#[cfg(feature = "matching")]
use regex::Regex;
#[cfg(feature = "matching")]
use std::fmt;
#[cfg(feature = "matching")]
use std::hash::{Hash, Hasher};
#[cfg(feature = "matching")]
use std::ops::Deref;

use crate::crypto::algorithm::Algorithm;
use crate::error::{Error, ErrorDetails};
use crate::raw::*;
use crate::TokenData;

// Regex doesn't implement PartialEq, Eq or Hash so we nee a wrapper...
#[cfg(feature = "matching")]
#[derive(Debug, Clone)]
struct Pattern(Regex);

#[cfg(feature = "matching")]
impl Deref for Pattern {
    type Target = Regex;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
#[cfg(feature = "matching")]
impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
#[cfg(feature = "matching")]
impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
#[cfg(feature = "matching")]
impl Eq for Pattern {}
#[cfg(feature = "matching")]
impl Hash for Pattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

#[derive(Clone)]
struct VerifierClosure {
    func: Arc<dyn Send + Sync + Fn(&serde_json::value::Value) -> bool>,
}
impl Eq for VerifierClosure {}
impl PartialEq for VerifierClosure {
    fn eq(&self, other: &Self) -> bool {
        // WARNING:
        //
        // `Arc::ptr_eq(&self.func, &other.func)` is effectively implemented as:
        //
        // `Arc::as_ptr(&arc_a) == Arc::as_ptr(&arc_b)`
        //
        // which will notably result in comparing the vtable pointer for (wide) trait object pointers
        // and does _not_ match the API documentation that states:
        //
        // > Returns true if the two Arcs point to the same allocation (in a vein similar to ptr::eq).
        //
        // (which is what we need here)
        //
        // See: https://github.com/rust-lang/rust/pull/80505
        //
        // To ensure we are comparing the data pointer component of any wide pointer then we
        // additionally cast `Arc::as_ptr(&arc)` to a thin pointer to discard the vtable
        //
        // This avoid getting a `clippy::vtable_address_comparisons` error
        //
        // Ref: https://github.com/rust-lang/rust-clippy/issues/6524

        let a = Arc::as_ptr(&self.func) as *const u8;
        let b = Arc::as_ptr(&other.func) as *const u8;
        std::ptr::eq(a, b)
    }
}
impl std::fmt::Debug for VerifierClosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VerifierClosure")
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
enum VerifierKind {
    Closure(VerifierClosure),

    StringConstant(String),
    StringSet(HashSet<String>),

    #[cfg(feature = "matching")]
    StringPattern(Pattern),
    #[cfg(feature = "matching")]
    StringPatternSet(HashSet<Pattern>),

    StringOrArrayContains(String),
}

/// Immutable requirements for checking token claims
#[derive(Clone)]
pub struct Verifier {
    leeway: u32,
    ignore_exp: bool,
    ignore_nbf: bool,
    ignore_iat: bool,

    claim_verifiers: HashMap<String, VerifierKind>,
}

impl Verifier {
    /// Start constructing a Verifier and configuring what claims should be verified.
    pub fn create() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    /// Verifies a token's claims but does not look at any header or verify any signature
    pub fn verify_claims_only(
        &self,
        claims: &serde_json::value::Value,
        time_now: u64,
    ) -> Result<(), Error> {
        let claims = match claims {
            serde_json::value::Value::Object(map) => map,
            _ => {
                return Err(Error::MalformedToken(ErrorDetails::new(
                    "Expected claims to be a JSON object",
                )))
            }
        };

        if !self.ignore_iat {
            match claims.get("iat") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(iat) = number.as_u64() {
                        if iat > time_now + (self.leeway as u64) {
                            return Err(Error::MalformedToken(ErrorDetails::new(
                                "Issued with a future 'iat' time",
                            )));
                        }
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new(
                            "Failed to parse 'iat' as an integer",
                        )));
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(
                        "Given 'iat' not a number",
                    )));
                }
                None => {}
            }
        }

        if !self.ignore_nbf {
            match claims.get("nbf") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(nbf) = number.as_u64() {
                        if nbf > time_now + (self.leeway as u64) {
                            return Err(Error::MalformedToken(ErrorDetails::new(
                                "Time is before 'nbf'",
                            )));
                        }
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new(
                            "Failed to parse 'nbf' as an integer",
                        )));
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(
                        "Given 'nbf' not a number",
                    )));
                }
                None => {}
            }
        }

        if !self.ignore_exp {
            match claims.get("exp") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(exp) = number.as_u64() {
                        if exp <= time_now - (self.leeway as u64) {
                            return Err(Error::TokenExpiredAt(exp));
                        }
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new(
                            "Failed to parse 'exp' as an integer",
                        )));
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(
                        "Given 'exp' not a number",
                    )));
                }
                None => {}
            }
        }

        // At least verify the type for these standard claims
        // (Values can separately be validated via .claim_verifiers)
        for &string_claim in &["iss", "sub"] {
            match claims.get(string_claim) {
                Some(serde_json::value::Value::String(_)) => {}
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                        "Given '{string_claim}' not a string"
                    ))));
                }
                None => {}
            }
        }

        for &string_or_array in &["aud"] {
            match claims.get(string_or_array) {
                Some(serde_json::value::Value::String(_)) => {}
                Some(serde_json::value::Value::Array(claim_array)) => {
                    for subclaim in claim_array {
                        if !subclaim.is_string() {
                            return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                "Claim {string_or_array}: array elements are not all strings"
                            ))));
                        }
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                        "Given '{string_or_array}' not a string or an array of strings"
                    ))));
                }
                None => {}
            }
        }

        let verifiers = &self.claim_verifiers;

        for (claim_key, claim_verifier) in verifiers.iter() {
            match claims.get(claim_key) {
                Some(claim_value) => {
                    if let VerifierKind::Closure(closure_container) = claim_verifier {
                        let closure = closure_container.func.as_ref();
                        if !closure(claim_value) {
                            return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                "Claim {claim_key}: verifier callback returned false for '{claim_value}'"
                            ))));
                        }
                    } else if let Value::String(claim_string) = claim_value {
                        match claim_verifier {
                            VerifierKind::StringConstant(constant) => {
                                if claim_string != constant {
                                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                        "Claim {claim_key}: {claim_string} != {constant}"
                                    ))));
                                }
                            }
                            VerifierKind::StringSet(constant_set) => {
                                if !constant_set.contains(claim_string) {
                                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                        "Claim {claim_key}: {claim_string} not in set"
                                    ))));
                                }
                            }
                            #[cfg(feature = "matching")]
                            VerifierKind::StringPattern(pattern) => {
                                if !pattern.is_match(claim_string) {
                                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                        "Claim {claim_key}: {claim_string} doesn't match regex {pattern}"
                                    ))));
                                }
                            }
                            #[cfg(feature = "matching")]
                            VerifierKind::StringPatternSet(pattern_set) => {
                                let mut found_match = false;
                                for p in pattern_set {
                                    if p.is_match(claim_string) {
                                        found_match = true;
                                        break;
                                    }
                                }
                                if !found_match {
                                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                        "Claim {claim_key}: {claim_string} doesn't match regex set"
                                    ))));
                                }
                            }
                            VerifierKind::StringOrArrayContains(contains) => {
                                if claim_string != contains {
                                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                        "Claim {claim_key}: {claim_string} != {contains}"
                                    ))));
                                }
                            }
                            _ => {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                    "Claim {claim_key}: has unexpected type (String)"
                                ))));
                            }
                        }
                    } else if let Value::Array(claim_array) = claim_value {
                        match claim_verifier {
                            VerifierKind::StringOrArrayContains(contains) => {
                                let mut found = false;
                                for subclaim in claim_array {
                                    match subclaim {
                                        Value::String(subclaim_string) => {
                                            if subclaim_string == contains {
                                                found = true;
                                                // XXX: don't break from loop early since we want to
                                                // check _all_ array elements are strings
                                            }
                                        }
                                        _ => {
                                            return Err(Error::MalformedToken(ErrorDetails::new(
                                                format!(
                                                    "Claim {claim_key}: array elements are not all strings"
                                                ),
                                            )));
                                        }
                                    }
                                }
                                if !found {
                                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                        "Claim {claim_key}: array did not contain '{contains}'"
                                    ))));
                                }
                            }
                            _ => {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!(
                                    "Claim {claim_key}: has unexpected type (Array)"
                                ))));
                            }
                        }
                    } else if let Value::Number(_claim_number) = claim_value {
                        // TODO: support verifying numeric claims
                        return Err(Error::MalformedToken(ErrorDetails::new(format!(
                            "Claim {claim_key}: has unexpected type (Number)"
                        ))));
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new(format!(
                            "Claim {claim_key}: has unexpected type"
                        ))));
                    }
                }
                _ => {
                    // If we have a verifier for particular claim then that claim is required
                    return Err(Error::MalformedToken(ErrorDetails::new(format!(
                        "Claim {claim_key}: missing"
                    ))));
                }
            }
        }
        Ok(())
    }

    /// Verify a token's signature and its claims, given a specific unix epoch timestamp
    pub fn verify_for_time(
        &self,
        token: impl AsRef<str>,
        algorithm: &Algorithm,
        time_now: u64,
    ) -> Result<TokenData, Error> {
        let TokenSlices {
            message,
            signature,
            header,
            claims,
        } = split_token(token.as_ref())?;

        let header = decode_json_token_slice(header)?;
        verify_signature_only(&header, message, signature, algorithm)?;
        let claims = decode_json_token_slice(claims)?;
        self.verify_claims_only(&claims, time_now)?;

        Ok(TokenData {
            header,
            claims,
            _extensible: (),
        })
    }

    /// Verify a token's signature and its claims
    pub fn verify(
        &self,
        token: impl AsRef<str>,
        algorithm: &Algorithm,
    ) -> Result<serde_json::value::Value, Error> {
        let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => {
                return Err(Error::InvalidInput(ErrorDetails::new(
                    "SystemTime before UNIX EPOCH!",
                )))
            }
        };

        match self.verify_for_time(token.as_ref(), algorithm, timestamp) {
            Ok(data) => Ok(data.claims),
            Err(error) => Err(error),
        }
    }
}

/// Configures the requirements for checking token claims with a builder-pattern API
#[derive(Debug, Default)]
pub struct VerifierBuilder {
    leeway: u32,
    ignore_exp: bool,
    ignore_nbf: bool,
    ignore_iat: bool,

    claim_verifiers: HashMap<String, VerifierKind>,
}

impl VerifierBuilder {
    pub fn new() -> VerifierBuilder {
        VerifierBuilder {
            leeway: 0,
            ignore_exp: false,
            ignore_nbf: false,
            ignore_iat: false,
            claim_verifiers: HashMap::new(),
        }
    }

    /// Convenience for string_equals("iss", "value")
    pub fn issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.string_equals("iss", issuer)
    }

    /// Convenience for string_or_array_contains("aud", "value")
    pub fn audience(&mut self, aud: impl Into<String>) -> &mut Self {
        self.string_or_array_contains("aud", aud)
    }

    /// Convenience for string_equals("sub", "value")
    pub fn subject(&mut self, sub: impl Into<String>) -> &mut Self {
        self.string_equals("sub", sub)
    }

    /// Convenience for string_equals("nonce", "value")
    pub fn nonce(&mut self, nonce: impl Into<String>) -> &mut Self {
        self.string_equals("nonce", nonce)
    }

    /// Check that a claim has a specific string value
    pub fn string_equals(
        &mut self,
        claim: impl Into<String>,
        value: impl Into<String>,
    ) -> &mut Self {
        self.claim_verifiers
            .insert(claim.into(), VerifierKind::StringConstant(value.into()));
        self
    }

    /// Check that a claim equals one of the given string values
    pub fn string_equals_one_of(&mut self, claim: impl Into<String>, values: &[&str]) -> &mut Self {
        let hash_set: HashSet<String> = values.iter().cloned().map(|s| s.to_owned()).collect();
        self.claim_verifiers
            .insert(claim.into(), VerifierKind::StringSet(hash_set));
        self
    }

    /// Check that the claim matches the given regular expression
    #[cfg(feature = "matching")]
    pub fn string_matches(
        &mut self,
        claim: impl Into<String>,
        value: impl Into<Regex>,
    ) -> &mut Self {
        self.claim_verifiers.insert(
            claim.into(),
            VerifierKind::StringPattern(Pattern(value.into())),
        );
        self
    }

    // Maybe this could be more ergonomic if it took &[&str] strings but then we'd have to
    // defer compiling the regular expressions until .build() which would be a bit of a pain

    /// Check that the claim matches one of the given regular expressions
    #[cfg(feature = "matching")]
    #[allow(clippy::mutable_key_type)]
    pub fn string_matches_one_of(
        &mut self,
        claim: impl Into<String>,
        values: &[Regex],
    ) -> &mut Self {
        let hash_set: HashSet<Pattern> = values.iter().cloned().map(Pattern).collect();
        self.claim_verifiers
            .insert(claim.into(), VerifierKind::StringPatternSet(hash_set));
        self
    }

    pub fn string_or_array_contains(
        &mut self,
        claim: impl Into<String>,
        value: impl Into<String>,
    ) -> &mut Self {
        self.claim_verifiers.insert(
            claim.into(),
            VerifierKind::StringOrArrayContains(value.into()),
        );
        self
    }

    /// Sets a leeway (in seconds) should be allowed when checking exp, nbf and iat claims
    pub fn leeway(&mut self, leeway: u32) -> &mut Self {
        self.leeway = leeway;
        self
    }

    /// Don't check the 'exp' expiry claim
    pub fn ignore_exp(&mut self) -> &mut Self {
        self.ignore_exp = true;
        self
    }

    /// Don't check the 'nbf' not before claim
    pub fn ignore_nbf(&mut self) -> &mut Self {
        self.ignore_nbf = true;
        self
    }

    /// Don't check the 'iat' issued at claim
    pub fn ignore_iat(&mut self) -> &mut Self {
        self.ignore_iat = true;
        self
    }

    /// Check a claim `Value` manually, returning `true` if ok, else `false`
    pub fn claim_callback(
        &mut self,
        claim: impl Into<String>,
        func: impl Send + Sync + Fn(&serde_json::value::Value) -> bool + 'static,
    ) -> &mut Self {
        let closure_verifier = VerifierClosure {
            func: Arc::new(func),
        };
        self.claim_verifiers
            .insert(claim.into(), VerifierKind::Closure(closure_verifier));
        self
    }

    /// Build the final Verifier
    pub fn build(&self) -> Result<Verifier, Error> {
        Ok(Verifier {
            leeway: self.leeway,
            ignore_exp: self.ignore_exp,
            ignore_nbf: self.ignore_nbf,
            ignore_iat: self.ignore_iat,
            claim_verifiers: self.claim_verifiers.clone(),
        })
    }
}
