use std::fmt;
use std::str::FromStr;
use std::ops::Deref;
use std::time::SystemTime;
use std::hash::{ Hash, Hasher };
use std::collections::{ HashSet, HashMap };
use regex::Regex;
use serde_json::map::Map;
use serde_json::value::Value;
use serde::de::DeserializeOwned;

use crate::{TokenSlices, get_token_slices, TokenData};
use crate::error::{Error, ErrorDetails};
use crate::crypto::{Algorithm, AlgorithmID};
use crate::serialization::parse_jwt_part;


// Regex doesn't implement PartialEq, Eq or Hash so we nee a wrapper...
#[derive(Debug, Clone)]
pub struct Pattern(Regex);

impl Deref for Pattern {
    type Target = Regex;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
impl PartialEq for Pattern {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for Pattern {}
impl Hash for Pattern {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.0.as_str().hash(state);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifierKind {
    Constant(String),
    Pattern(Pattern),
    Set(HashSet<String>),
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

    claim_validators: HashMap<String, VerifierKind>,

    #[doc(hidden)]
    _extensible: (),
}

impl Verifier {

    pub fn create() -> VerifierBuilder {
        VerifierBuilder::new()
    }

    /// Used to verify the header and claims
    fn verify_part(&self, jwt_part: &Map<String, Value>, validators: &HashMap<String, VerifierKind>) -> Result<(), Error> {

        for (claim_key, claim_verifier) in validators.iter() {
            match jwt_part.get(claim_key) {
                Some(Value::String(claim_string)) => {
                    match claim_verifier {
                        VerifierKind::Constant(constant) => {
                            if claim_string != constant {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} != {}", claim_key, claim_string, constant))));
                            }
                        },
                        VerifierKind::Pattern(pattern) => {
                            if !pattern.is_match(claim_string) {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} doesn't match regex {}", claim_key, claim_string, pattern))));
                            }
                        },
                        VerifierKind::Set(constant_set) => {
                            if !constant_set.contains(claim_string) {
                                return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} not in set", claim_key, claim_string))));
                            }
                        },
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
                        VerifierKind::__Nonexhaustive => unreachable!("Unhandled claim validator kind")
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

    pub async fn verify_for_time(
        &self,
        token: impl AsRef<str>,
        algorithm: &Algorithm,
        time_now: u64
    ) -> Result<TokenData, Error>
    {
        let TokenSlices {message, signature, header, claims } = get_token_slices(token.as_ref())?;
        let header = parse_jwt_part(header)?;

        match header.get("alg") {
            Some(serde_json::value::Value::String(alg)) => {
                let alg = AlgorithmID::from_str(alg)?;

                if alg != algorithm.get_id() {
                    return Err(Error::AlgorithmMismatch());
                }

                // We want the Algorithm verifier to be able to abstract a key set in the future so we
                // need to pass it any 'kid' if available...
                let kid = match header.get("kid") {
                    Some(serde_json::value::Value::String(k)) => Some(k.as_ref()),
                    Some(_) => return Err(Error::MalformedToken(ErrorDetails::new("Non-string 'kid' found"))),
                    None => None
                };

                algorithm.verify(kid, message, signature).await?;
            },
            _ => return Err(Error::AlgorithmMismatch())
        }

        let claims = parse_jwt_part(claims)?;

        if ! self.ignore_iat {
            match claims.get("iat") {
                Some(serde_json::value::Value::Number(number)) => {
                    if let Some(iat) = number.as_u64() {
                        if iat > time_now - (self.leeway as u64) {
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
                        if nbf >= time_now + (self.leeway as u64) {
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
                        if exp < time_now - (self.leeway as u64) {
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
        // (Values can separately be validated via .claim_validators)
        for &string_claim in &[ "iss", "sub", "aud", "" ] {
            match claims.get(string_claim) {
                Some(serde_json::value::Value::String(_)) => {}
                Some(_) => {
                    return Err(Error::MalformedToken(ErrorDetails::new(format!("Given '{}' not a string", string_claim))));
                }
                None => {}
            }
        }

        self.verify_part(&claims, &self.claim_validators)?;

        Ok(TokenData { header: header, claims: Some(claims), _extensible: () })
    }

    pub async fn verify<C: DeserializeOwned, T: AsRef<str>>(
        &self,
        token: T,
        algorithm: &Algorithm,
    ) -> Result<C, Error>
    {
        let timestamp = match SystemTime::now().duration_since(SystemTime::UNIX_EPOCH) {
            Ok(n) => n.as_secs(),
            Err(_) => return Err(Error::InvalidInput(ErrorDetails::new("SystemTime before UNIX EPOCH!"))),
        };

        match self.verify_for_time(token.as_ref(), algorithm, timestamp).await {
            Ok(data) => {
                if let Some(claims) = data.claims {
                    let claims = serde_json::value::Value::Object(claims);
                    serde_json::from_value(claims)
                        .map_err(|e| Error::MalformedToken(ErrorDetails::map("Failed to deserialize json into custom claims struct", e)))
                } else {
                    Err(Error::InvalidInput(ErrorDetails::new("No claims to deserialize")))
                }
            },
            Err(error) => Err(error)
        }
    }
}

pub struct VerifierBuilder {
    leeway: u32,
    ignore_exp: bool,
    ignore_nbf: bool,
    ignore_iat: bool,

    claim_validators: HashMap<String, VerifierKind>,

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
            claim_validators: HashMap::new(),
            _extensible: ()
        }
    }

    /// Convenience for claim_equals("iss", "value")
    pub fn issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.claim_equals("iss", issuer)
    }

    /// Convenience for claim_equals("aud", "value")
    pub fn audience(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.claim_equals("aud", issuer)
    }

    /// Convenience for claim_equals("sub", "value")
    pub fn subject(&mut self, sub: impl Into<String>) -> &mut Self {
        self.claim_equals("sub", sub)
    }

    /// Convenience for claim_equals("nonce", "value")
    pub fn nonce(&mut self, nonce: impl Into<String>) -> &mut Self {
        self.claim_equals("nonce", nonce)
    }

    pub fn claim_equals(&mut self, claim: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.claim_validators.insert(claim.into(), VerifierKind::Constant(value.into()));
        self
    }

    pub fn claim_equals_one_of(&mut self, claim: impl Into<String>, values: &[&str]) -> &mut Self
    {
        let hash_set: HashSet<String> = values.into_iter().cloned().map(|s| s.to_owned()).collect();
        self.claim_validators.insert(claim.into(), VerifierKind::Set(hash_set));
        self
    }

    pub fn claim_matches(&mut self, claim: impl Into<String>, value: impl Into<Regex>) -> &mut Self {
        self.claim_validators.insert(claim.into(), VerifierKind::Pattern(Pattern(value.into())));
        self
    }

    // Maybe this could be more ergonomic if it took &[&str] strings but then we'd have to
    // defer compiling the regular expressions until .build() which would be a bit of a pain
    pub fn claim_matches_one_of(&mut self, claim: impl Into<String>, values: &[Regex]) -> &mut Self
    {
        let hash_set: HashSet<Pattern> = values
            .into_iter()
            .cloned()
            .map(|r| Pattern(r))
            .collect();
        self.claim_validators.insert(claim.into(), VerifierKind::PatternSet(hash_set));
        self
    }

    pub fn accept_leeway(&mut self, leeway: u32) -> &mut Self {
        self.leeway = leeway;
        self
    }

    pub fn ignore_exp(&mut self) -> &mut Self {
        self.ignore_exp = true;
        self
    }

    pub fn ignore_nbf(&mut self) -> &mut Self {
        self.ignore_nbf = true;
        self
    }

    pub fn ignore_iat(&mut self) -> &mut Self {
        self.ignore_iat = true;
        self
    }

    pub fn build(&self) -> Result<Verifier, Error> {
        Ok(Verifier {
            leeway: self.leeway,
            ignore_exp: self.ignore_exp,
            ignore_nbf: self.ignore_nbf,
            ignore_iat: self.ignore_iat,
            claim_validators: self.claim_validators.clone(),
            _extensible: ()
        })
    }
}