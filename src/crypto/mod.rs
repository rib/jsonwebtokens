use ring::signature;

pub(crate) mod algorithm;
pub(crate) mod ecdsa;
pub(crate) mod hmac;
pub(crate) mod rsa;

#[derive(Debug)]
pub enum SecretOrKey {
    // Unsecured
    None,

    // HMAC
    Secret(Vec<u8>),

    // ECDSA
    EcdsaKeyPair(Box<signature::EcdsaKeyPair>),
    EcdsaUnparsedKey(Vec<u8>),

    // RSA
    RsaKeyPair(Box<signature::RsaKeyPair>),
    RsaUnparsedKey(Vec<u8>),
    RsaParameters(Vec<u8>, Vec<u8>), // (n, e)
}
