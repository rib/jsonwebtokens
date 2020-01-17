use std::time::SystemTime;
use std::collections::{ HashSet, HashMap };
use serde_json::value::Value;

#[cfg(feature = "matching")]
use std::fmt;
#[cfg(feature = "matching")]
use std::ops::Deref;
#[cfg(feature = "matching")]
use std::hash::{ Hash, Hasher };
#[cfg(feature = "matching")]
use regex::Regex;

use crate::error::{Error, ErrorDetails};
use crate::TokenData;
use crate::raw::*;
use crate::crypto::algorithm::{Algorithm};


// Regex doesn't implement PartialEq, Eq or Hash so we nee a wrapper...
#[cfg(feature = "matching")]
#[derive(Debug, Clone)]
pub struct Pattern(Regex);

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

#[derive(Debug, Clone, PartialEq, Eq)]
enum VerifierKind {
    Constant(String),
    Set(HashSet<String>),

    #[cfg(feature = "matching")]
    Pattern(Pattern),
    #[cfg(feature = "matching")]
    PatternSet(HashSet<Pattern>),

    #[doc(hidden)]
    __Nonexhaustive
}

#[derive(Debug, Clone)]
pub struct Verifier {
    leeway: u32,
    ignore_exp: bool,
    ignore_nbf: bool,
    ignore_iat: bool,

    claim_verifiers: HashMap<String, VerifierKind>,

    #[doc(hidden)]
    _extensible: (),
}

impl Verifier {

    /// Start constructing a Verifier and configuring what claims should be verified.
    pub fn create() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    /// Verifies a token's claims but does not look at any header or verify any signature
    pub fn verify_claims_only(&self, claims: &serde_json::value::Value, time_now: u64) -> Result<(), Error> {

        let claims = match claims {
            serde_json::value::Value::Object(map) => map,
            _ => return Err(Error::MalformedToken(ErrorDetails::new("Expected claims to be a JSON object")))
        };

        if ! self.ignore_iat {
            match claims.get("iat") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(iat) = number.as_u64() {
                        if iat > time_now + (self.leeway as u64) {
                            return Err(Error::MalformedToken(ErrorDetails::new("Issued with a future 'iat' time")));
                        }
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new("Failed to parse 'iat' as an integer")));
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new("Given 'iat' not a number")));
                }
                None => {}
            }
        }

        if ! self.ignore_nbf {
            match claims.get("nbf") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(nbf) = number.as_u64() {
                        if nbf > time_now + (self.leeway as u64) {
                            return Err(Error::MalformedToken(ErrorDetails::new("Time is before 'nbf'")));
                        }
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new("Failed to parse 'nbf' as an integer")));
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new("Given 'nbf' not a number")));
                }
                None => {}
            }
        }

        if ! self.ignore_exp {
            match claims.get("exp") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(exp) = number.as_u64() {
                        if exp <= time_now - (self.leeway as u64) {
                            return Err(Error::TokenExpiredAt(exp));
                        }
                    } else {
                        return Err(Error::MalformedToken(ErrorDetails::new("Failed to parse 'exp' as an integer")));
                    }
                }
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new("Given 'exp' not a number")));
                }
                None => {}
            }
        }

        // At least verify the type for these standard claims
        // (Values can separately be validated via .claim_verifiers)
        for &string_claim in &[ "iss", "sub", "aud", "" ] {
            match claims.get(string_claim) {
                Some(serde_json::value::Value::String(_)) => {}
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(format!("Given '{}' not a string", string_claim))));
                }
                None => {}
            }
        }

        let verifiers = &self.claim_verifiers;

        for (claim_key, claim_verifier) in verifiers.iter() {
            match claims.get(claim_key) {
                Some(Value::String(claim_string)) => {
                    match claim_verifier {
                        VerifierKind::Constant(constant) => {
                            if claim_string != constant {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} != {}", claim_key, claim_string, constant))));
                            }
                        },
                        VerifierKind::Set(constant_set) => {
                            if !constant_set.contains(claim_string) {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} not in set", claim_key, claim_string))));
                            }
                        },
                        #[cfg(feature = "matching")]
                        VerifierKind::Pattern(pattern) => {
                            if !pattern.is_match(claim_string) {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} doesn't match regex {}", claim_key, claim_string, pattern))));
                            }
                        },
                        #[cfg(feature = "matching")]
                        VerifierKind::PatternSet(pattern_set) => {
                            let mut found_match = false;
                            for p in pattern_set {
                                if p.is_match(claim_string) {
                                    found_match = true;
                                    break;
                                }
                            }
                            if !found_match {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} doesn't match regex set",
                                                                                        claim_key, claim_string))));
                            }
                        }
                        VerifierKind::__Nonexhaustive => unreachable!("Unhandled claim verifier kind")
                    }
                }
                _ => {
                    // If we have a verifier for particular claim then that claim is required
                    return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: missing, or not a string", claim_key))));
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
        time_now: u64
    ) -> Result<TokenData, Error>
    {
        let TokenSlices {message, signature, header, claims } = split_token(token.as_ref())?;

        let header = decode_json_token_slice(header)?;
        verify_signature_only(&header, message, signature, algorithm)?;
        let claims = decode_json_token_slice(claims)?;
        self.verify_claims_only(&claims, time_now)?;

        Ok(TokenData { header: header, claims: claims, _extensible: () })
    }

    /// Verify a token's signature and its claims
    pub fn verify(
        &self,
        token: impl AsRef<str>,
        algorithm: &Algorithm,
    ) -> Result<serde_json::value::Value, Error>
    {
        let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => return Err(Error::InvalidInput(ErrorDetails::new("SystemTime before UNIX EPOCH!"))),
        };

        match self.verify_for_time(token.as_ref(), algorithm, timestamp) {
            Ok(data) => Ok(data.claims),
            Err(error) => Err(error)
        }
    }
}

pub struct VerifierBuilder {
    leeway: u32,
    ignore_exp: bool,
    ignore_nbf: bool,
    ignore_iat: bool,

    claim_verifiers: HashMap<String, VerifierKind>,

    #[doc(hidden)]
    _extensible: (),
}

impl VerifierBuilder {

    pub fn new() -> VerifierBuilder {
        VerifierBuilder {
            leeway: 0,
            ignore_exp: false,
            ignore_nbf: false,
            ignore_iat: false,
            claim_verifiers: HashMap::new(),
            _extensible: ()
        }
    }

    /// Convenience for string_equals("iss", "value")
    pub fn issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.string_equals("iss", issuer)
    }

    /// Convenience for string_equals("aud", "value")
    pub fn audience(&mut self, aud: impl Into<String>) -> &mut Self {
        self.string_equals("aud", aud)
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
    pub fn string_equals(&mut self, claim: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.claim_verifiers.insert(claim.into(), VerifierKind::Constant(value.into()));
        self
    }

    /// Check that a claim equals one of the given string values
    pub fn string_equals_one_of(&mut self, claim: impl Into<String>, values: &[&str]) -> &mut Self
    {
        let hash_set: HashSet<String> = values.into_iter().cloned().map(|s| s.to_owned()).collect();
        self.claim_verifiers.insert(claim.into(), VerifierKind::Set(hash_set));
        self
    }

    /// Check that the claim matches the given regular expression
    #[cfg(feature = "matching")]
    pub fn string_matches(&mut self, claim: impl Into<String>, value: impl Into<Regex>) -> &mut Self {
        self.claim_verifiers.insert(claim.into(), VerifierKind::Pattern(Pattern(value.into())));
        self
    }

    // Maybe this could be more ergonomic if it took &[&str] strings but then we'd have to
    // defer compiling the regular expressions until .build() which would be a bit of a pain

    /// Check that the claim matches one of the given regular expressions
    #[cfg(feature = "matching")]
    pub fn string_matches_one_of(&mut self, claim: impl Into<String>, values: &[Regex]) -> &mut Self
    {
        let hash_set: HashSet<Pattern> = values
            .into_iter()
            .cloned()
            .map(|r| Pattern(r))
            .collect();
        self.claim_verifiers.insert(claim.into(), VerifierKind::PatternSet(hash_set));
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

    /// Build the final Verifier
    pub fn build(&self) -> Result<Verifier, Error> {
        Ok(Verifier {
            leeway: self.leeway,
            ignore_exp: self.ignore_exp,
            ignore_nbf: self.ignore_nbf,
            ignore_iat: self.ignore_iat,
            claim_verifiers: self.claim_verifiers.clone(),
            _extensible: ()
        })
    }
}