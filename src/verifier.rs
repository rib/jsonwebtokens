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
        for claim_key in jwt_part.keys() {
            if let Some(value) = validators.get(claim_key) {
                let claim_value = match jwt_part.get(claim_key) {
                    Some(serde_json::value::Value::String(claim_string)) => claim_string,
                    _ => return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: string not found", claim_key))))
                };

                match value {
                    VerifierKind::Constant(constant) => {
                        if claim_value != constant {
                            return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} != {}", claim_key, claim_value, constant))));
                        }
                    },
                    VerifierKind::Pattern(pattern) => {
                        if !pattern.is_match(claim_value) {
                            return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} doesn't match regex {}", claim_key, claim_value, pattern))));
                        }
                    },
                    VerifierKind::Set(constant_set) => {
                        if !constant_set.contains(claim_value) {
                            return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} not in set", claim_key, claim_value))));
                        }
                    },
                    VerifierKind::PatternSet(pattern_set) => {
                        let mut found_match = false;
                        for p in pattern_set {
                            if p.is_match(claim_value) {
                                found_match = true;
                                break;
                            }
                        }
                        if !found_match {
                            return Err(Error::MalformedToken(ErrorDetails::new(format!("{}: {} doesn't match regex set",
                                                                                       claim_key, claim_value))));
                        }
                    }
                    VerifierKind::__Nonexhaustive => unreachable!("Unhandled claim validator kind")
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

        if ! self.ignore_nbf {
            if let Some(serde_json::value::Value::Number(number)) = claims.get("nbf") {
                if let Some(nbf) = number.as_u64() {
                    if nbf >= time_now + (self.leeway as u64) {
                        return Err(Error::MalformedToken(ErrorDetails::new("Time is before 'nbf'")));
                    }
                } else {
                    return Err(Error::MalformedToken(ErrorDetails::new("Failed to parse 'nbf' as number")));
                }
            }
        }

        if ! self.ignore_exp {
            if let Some(serde_json::value::Value::Number(number)) = claims.get("exp") {
                if let Some(exp) = number.as_u64() {
                    if exp < time_now - (self.leeway as u64) {
                        return Err(Error::TokenExpiredAt(exp));
                    }
                } else {
                    return Err(Error::MalformedToken(ErrorDetails::new("Failed to parse 'exp' as number")));
                }
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
            claim_validators: HashMap::new(),
            _extensible: ()
        }
    }

    /// Convenience for claim_equals("iss", "value")
    pub fn with_issuer(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.claim_equals("iss", issuer)
    }

    /// Convenience for claim_equals("aud", "value")
    pub fn with_audience(&mut self, issuer: impl Into<String>) -> &mut Self {
        self.claim_equals("aud", issuer)
    }

    pub fn claim_equals(&mut self, claim: impl Into<String>, value: impl Into<String>) -> &mut Self {
        self.claim_validators.insert(claim.into(), VerifierKind::Constant(value.into()));
        self
    }
    pub fn claim_equals_one_of(&mut self, claim: impl Into<String>, values: HashSet<String>) -> &mut Self {
        self.claim_validators.insert(claim.into(), VerifierKind::Set(values));
        self
    }

    pub fn claim_matches(&mut self, claim: impl Into<String>, value: impl Into<Regex>) -> &mut Self {
        self.claim_validators.insert(claim.into(), VerifierKind::Pattern(Pattern(value.into())));
        self
    }
    pub fn claim_matches_one_of(&mut self, claim: impl Into<String>, values: HashSet<Pattern>) -> &mut Self {
        self.claim_validators.insert(claim.into(), VerifierKind::PatternSet(values));
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

    pub fn build(&self) -> Result<Verifier, Error> {
        Ok(Verifier {
            leeway: self.leeway,
            ignore_exp: self.ignore_exp,
            ignore_nbf: self.ignore_nbf,
            claim_validators: self.claim_validators.clone(),
            _extensible: ()
        })
    }
}