//! Regroup key derivation functions required in the protocol

use std::convert::TryFrom;

use hkdf::Hkdf;
use sha3::{Digest, Sha3_256};

use crate::alias::{OutputKey, VerifyTag, KEY_SIZE};

static STR_CLIENT_MAC: &[u8] = b"ClientMAC";
static STR_HANDSHAKE_SECRET: &[u8] = b"HandshakeSecret";
static STR_SERVER_MAC: &[u8] = b"ServerMAC";
static STR_SESSION_KEY: &[u8] = b"SessionKey";
static STR_KHAPE: &[u8] = b"KHAPE-";
const STR_ENCRYPTION_KEY: &[u8; 13] = b"EncryptionKey";
const STR_EXPORT_KEY: &[u8; 9] = b"ExportKey";

type HkdfSha256 = Hkdf<Sha3_256>;


#[derive(Debug, Clone, PartialEq)]
pub struct KeyExchangeOutput {
    pub(crate) output_key: OutputKey,
    pub(crate) client_verify_tag: VerifyTag,
    pub(crate) server_verify_tag: VerifyTag
}


fn compute_hkdf(hkdf: &HkdfSha256, label: &[u8], context: &[u8]) -> Vec<u8> {
    let length: usize = Sha3_256::output_size();
    let mut okm = vec![0u8; length];

    let mut hkdf_label: Vec<u8> = Vec::new();

    hkdf_label.extend_from_slice(&u8::try_from(length).unwrap().to_be_bytes());
    hkdf_label.extend_from_slice(STR_KHAPE);
    hkdf_label.extend_from_slice(label);
    hkdf_label.extend_from_slice(context);

    hkdf.expand(&hkdf_label, &mut okm).unwrap();
    okm
}

/// Derive multiple keys from the 3DH key exchange output. The output key of the protocol and both verification tag.
/// This design is inspired by the OPAQUE's standard draft and OPAQUE-ke library
pub(crate) fn compute_output_key_and_tag(secret: &[u8], context: &[u8]) -> KeyExchangeOutput {
    let hkdf = HkdfSha256::new(None, &secret);
    let output_key = compute_hkdf(&hkdf, STR_SESSION_KEY, context);
    let handshake_secret = compute_hkdf(&hkdf, STR_HANDSHAKE_SECRET, context);

    let handshake_hkdf = HkdfSha256::from_prk(&handshake_secret).unwrap();
    let client_verify_tag = compute_hkdf(&handshake_hkdf, STR_CLIENT_MAC, b"");
    let server_verify_tag = compute_hkdf(&handshake_hkdf, STR_SERVER_MAC, b"");

    KeyExchangeOutput {
        output_key: <[u8; KEY_SIZE]>::try_from(output_key).unwrap(),
        client_verify_tag: <[u8; KEY_SIZE]>::try_from(client_verify_tag).unwrap(),
        server_verify_tag: <[u8; KEY_SIZE]>::try_from(server_verify_tag).unwrap()
    }
}

/// Derive multiple keys from the hardened OPRF output. The envelope encryption key and the export key.
/// This design is inspired by the OPAQUE's standard draft and OPAQUE-ke library
pub(crate) fn compute_envelope_key(oprf_output: Vec<u8>, hardened_output: Vec<u8>) -> ([u8; KEY_SIZE], [u8; KEY_SIZE]) {
    let mut encryption_key = vec![0u8; KEY_SIZE];
    let mut export_key = vec![0u8; KEY_SIZE];

    let hkdf = HkdfSha256::new(
        None,
        &[oprf_output, hardened_output].concat()
    );

    hkdf.expand(STR_ENCRYPTION_KEY, &mut encryption_key).unwrap();
    hkdf.expand(STR_EXPORT_KEY, &mut export_key).unwrap();

    (
        <[u8; KEY_SIZE]>::try_from(encryption_key).unwrap(),
        <[u8; KEY_SIZE]>::try_from(export_key).unwrap()
    )
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_output_key_and_tag() {
        let secret = b"19823iojda98s710iio23juiah";
        let context = b"";
        let ke_output = compute_output_key_and_tag(secret, context);

        assert_eq!(ke_output.output_key.len(), KEY_SIZE);
        assert_eq!(ke_output.server_verify_tag.len(), KEY_SIZE);
        assert_eq!(ke_output.client_verify_tag.len(), KEY_SIZE);
    }

    #[test]
    fn test_compute_output_key_and_tag_with_same_secret() {
        let secret = b"19823iojda98s710iio23juiah";
        let context = b"";
        let ke_output1 = compute_output_key_and_tag(secret, context);
        let ke_output2 = compute_output_key_and_tag(secret, context);

        assert_eq!(ke_output1, ke_output2)
    }

    #[test]
    fn test_compute_output_key_and_tag_with_different_secret() {
        let secret1 = b"19823iojda98s710iio23juiah";
        let secret2 = b"19823iojda98s710iio23juiai";
        let context = b"";
        assert_ne!(secret1, secret2);

        let ke_output1 = compute_output_key_and_tag(secret1, context);
        let ke_output2 = compute_output_key_and_tag(secret2, context);

        assert_ne!(ke_output1, ke_output2)
    }

    #[test]
    fn test_compute_output_key_and_tag_with_different_context() {
        let secret = b"19823iojda98s710iio23juiah";
        let context1 = b"0";
        let context2 = b"1";
        assert_ne!(context1, context2);

        let ke_output1 = compute_output_key_and_tag(secret, context1);
        let ke_output2 = compute_output_key_and_tag(secret, context2);

        assert_ne!(ke_output1, ke_output2)
    }

}