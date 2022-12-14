use crate::error::{Error, ErrorDetails};

/// Supported PEM files for EC and RSA Public and Private Keys
#[derive(Debug, PartialEq)]
enum PemType {
    EcPublic,
    EcPrivate,
    RsaPublic,
    RsaPrivate,
}

#[derive(Debug, PartialEq)]
enum Standard {
    // Only for RSA
    Pkcs1,
    // Only for EC
    Sec1,
    // RSA/EC
    Pkcs8,
}

#[derive(Debug, PartialEq)]
enum Classification {
    Ec,
    Rsa,
}

/// The return type of a successful PEM encoded key with `decode_pem`
///
/// This struct gives a way to parse a string to a key for our use.
/// A struct is necessary as it provides the lifetime of the key
///
/// PEM public private keys are encoded PKCS#1 or PKCS#8
/// You will find that with PKCS#8 RSA keys that the PKCS#1 content
/// is embedded inside. This is what is provided to ring via `Key::Der`
/// For EC keys, they are always PKCS#8 on the outside but like RSA keys
/// EC keys contain a section within that ultimately has the configuration
/// that ring uses.
/// Documentation about these formats is at
/// PKCS#1: https://tools.ietf.org/html/rfc8017
/// PKCS#8: https://tools.ietf.org/html/rfc5958
#[derive(Debug)]
pub(crate) struct PemEncodedKey {
    content: Vec<u8>,
    asn1: Vec<simple_asn1::ASN1Block>,
    pem_type: PemType,
    standard: Standard,
}

impl PemEncodedKey {
    /// Read the PEM file for later key use
    pub fn new(input: &[u8]) -> Result<PemEncodedKey, Error> {
        match pem::parse(input) {
            Ok(content) => {
                let pem_contents = content.contents;
                let asn1_content = match simple_asn1::from_der(pem_contents.as_slice()) {
                    Ok(asn1) => asn1,
                    Err(e) => {
                        return Err(Error::InvalidInput(ErrorDetails::map(
                            "Failed to parse PEM file",
                            Box::new(e),
                        )))
                    }
                };

                match content.tag.as_ref() {
                    // This handles a PKCS#1 RSA Private key
                    "RSA PRIVATE KEY" => Ok(PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::RsaPrivate,
                        standard: Standard::Pkcs1,
                    }),
                    "RSA PUBLIC KEY" => Ok(PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::RsaPublic,
                        standard: Standard::Pkcs1,
                    }),

                    // https://security.stackexchange.com/questions/84327/converting-ecc-private-key-to-pkcs1-format
                    // "there is no such thing as a "PKCS#1 format" for elliptic curve (EC) keys"

                    // At least recognize the key format specified in SEC 1: Elliptic Curve Cryptography
                    // Ring doesn't support this so it will lead to an error, but at least we can give a meaningful error
                    // (There's no equivalent standard for public EC keys)
                    "EC PRIVATE KEY" => Ok(PemEncodedKey {
                        content: pem_contents,
                        asn1: asn1_content,
                        pem_type: PemType::EcPrivate,
                        standard: Standard::Sec1,
                    }),

                    // This handles PKCS#8 public & private keys
                    tag @ "PRIVATE KEY" | tag @ "PUBLIC KEY" | tag @ "CERTIFICATE" => {
                        match classify_pem(&asn1_content) {
                            Some(c) => {
                                let is_private = tag == "PRIVATE KEY";
                                let pem_type = match c {
                                    Classification::Ec => {
                                        if is_private {
                                            PemType::EcPrivate
                                        } else {
                                            PemType::EcPublic
                                        }
                                    }
                                    Classification::Rsa => {
                                        if is_private {
                                            PemType::RsaPrivate
                                        } else {
                                            PemType::RsaPublic
                                        }
                                    }
                                };
                                Ok(PemEncodedKey {
                                    content: pem_contents,
                                    asn1: asn1_content,
                                    pem_type,
                                    standard: Standard::Pkcs8,
                                })
                            }
                            None => Err(Error::InvalidInput(ErrorDetails::new(
                                "Failed to recognize any OID in PKCS#8 PEM file",
                            ))),
                        }
                    }

                    _ => Err(Error::InvalidInput(ErrorDetails::new(
                        "Failed to recognize PKCS#1 or SEC1 or PKCS#8 markers in PEM file",
                    ))),
                }
            }
            Err(e) => Err(Error::InvalidInput(ErrorDetails::map(
                "Failed to parse PEM file",
                Box::new(e),
            ))),
        }
    }

    pub fn as_ec_private_key(&self) -> Result<&[u8], Error> {
        match self.standard {
            Standard::Pkcs1 => Err(Error::InvalidInput(ErrorDetails::new(
                "Expected PKCS#8 PEM markers, not PKCS#1",
            ))),
            Standard::Sec1 => Err(Error::InvalidInput(ErrorDetails::new(
                "Expected PKCS#8 PEM markers, not SEC1",
            ))),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EcPrivate => Ok(self.content.as_slice()),
                _ => Err(Error::InvalidInput(ErrorDetails::new(
                    "PEM key type mismatch (expected EC private key)",
                ))),
            },
        }
    }

    pub fn as_ec_public_key(&self) -> Result<&[u8], Error> {
        match self.standard {
            Standard::Pkcs1 => Err(Error::InvalidInput(ErrorDetails::new(
                "Expected PKCS#8 PEM markers, not PKCS#1",
            ))),
            Standard::Sec1 => Err(Error::InvalidInput(ErrorDetails::new(
                "Expected PKCS#8 PEM markers, not SEC1",
            ))),
            Standard::Pkcs8 => match self.pem_type {
                PemType::EcPublic => extract_first_bitstring(&self.asn1),
                _ => Err(Error::InvalidInput(ErrorDetails::new(
                    "PEM key type mismatch (expected EC public key)",
                ))),
            },
        }
    }

    pub fn as_rsa_public_key(&self) -> Result<&[u8], Error> {
        match self.standard {
            Standard::Pkcs1 => match self.pem_type {
                PemType::RsaPublic => Ok(self.content.as_slice()),
                _ => Err(Error::InvalidInput(ErrorDetails::new(
                    "PEM key type mismatch (expected RSA public key)",
                ))),
            },
            Standard::Sec1 => Err(Error::InvalidInput(ErrorDetails::new(
                "Expected PKCS#1 or PKCS#8 PEM markers, not SEC1",
            ))),
            Standard::Pkcs8 => match self.pem_type {
                PemType::RsaPublic => extract_first_bitstring(&self.asn1),
                _ => Err(Error::InvalidInput(ErrorDetails::new(
                    "PEM key type mismatch (expected RSA public key)",
                ))),
            },
        }
    }

    pub fn as_rsa_private_key(&self) -> Result<&[u8], Error> {
        match self.standard {
            Standard::Pkcs1 => match self.pem_type {
                PemType::RsaPrivate => Ok(self.content.as_slice()),
                _ => Err(Error::InvalidInput(ErrorDetails::new(
                    "PEM key type mismatch (expected RSA private key)",
                ))),
            },
            Standard::Sec1 => Err(Error::InvalidInput(ErrorDetails::new(
                "Expected PKCS#1 or PKCS#8 PEM markers, not SEC1",
            ))),
            Standard::Pkcs8 => match self.pem_type {
                PemType::RsaPrivate => extract_first_bitstring(&self.asn1),
                _ => Err(Error::InvalidInput(ErrorDetails::new(
                    "PEM key type mismatch (expected RSA private key)",
                ))),
            },
        }
    }
}

// This really just finds and returns the first bitstring or octet string
// Which is the x coordinate for EC public keys
// And the DER contents of an RSA key
// Though PKCS#11 keys shouldn't have anything else.
// It will get confusing with certificates.
fn extract_first_bitstring(asn1: &[simple_asn1::ASN1Block]) -> Result<&[u8], Error> {
    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Ok(result) = extract_first_bitstring(entries) {
                    return Ok(result);
                }
            }
            simple_asn1::ASN1Block::BitString(_, _, value) => {
                return Ok(value.as_ref());
            }
            simple_asn1::ASN1Block::OctetString(_, value) => {
                return Ok(value.as_ref());
            }
            _ => (),
        }
    }

    Err(Error::InvalidInput(ErrorDetails::new(
        "Failed to extract ASN.1 bit string",
    )))
}

/// Find whether this is EC or RSA
fn classify_pem(asn1: &[simple_asn1::ASN1Block]) -> Option<Classification> {
    // These should be constant but the macro requires
    // #![feature(const_vec_new)]
    let ec_public_key_oid = simple_asn1::oid!(1, 2, 840, 10_045, 2, 1);
    let rsa_public_key_oid = simple_asn1::oid!(1, 2, 840, 113_549, 1, 1, 1);

    for asn1_entry in asn1.iter() {
        match asn1_entry {
            simple_asn1::ASN1Block::Sequence(_, entries) => {
                if let Some(classification) = classify_pem(entries) {
                    return Some(classification);
                }
            }
            simple_asn1::ASN1Block::ObjectIdentifier(_, oid) => {
                if oid == ec_public_key_oid {
                    return Some(Classification::Ec);
                }
                if oid == rsa_public_key_oid {
                    return Some(Classification::Rsa);
                }
            }
            _ => {}
        }
    }
    None
}
