use sha3::{Sha3_256, Digest};
use hkdf::Hkdf;
use std::convert::TryFrom;

pub(crate) fn hash(data: &[u8]) -> [u8; 32] { // TODO use or remove
    <[u8; 32]>::from(Sha3_256::digest(data)) // TODO hardcoded [u8; 32] for sha256
}

pub(crate) fn slow_hash(content: Vec<u8>) -> Vec<u8> {
    unimplemented!();
}

pub(crate) fn hkdf_envelope_key(content: Vec<u8>, content2: Vec<u8>) -> Vec<u8> {
    unimplemented!();
}

static STR_CLIENT_MAC: &[u8] = b"ClientMAC";
static STR_HANDSHAKE_SECRET: &[u8] = b"HandshakeSecret";
static STR_SERVER_MAC: &[u8] = b"ServerMAC";
static STR_SESSION_KEY: &[u8] = b"SessionKey";
static STR_KHAPE: &[u8] = b"KHAPE-";

type HkdfSha256 = Hkdf<Sha3_256>;


fn compute_hkdf(hkdf: &HkdfSha256, label: &[u8], context: &[u8]) -> Vec<u8> {
    let length: usize = Sha3_256::output_size();
    let mut okm = vec![0u8; length];

    let mut hkdf_label: Vec<u8> = Vec::new();

    hkdf_label.extend_from_slice(&u8::try_from(length).unwrap().to_be_bytes());
    hkdf_label.extend_from_slice(STR_KHAPE);
    hkdf_label.extend_from_slice(label);
    hkdf_label.extend_from_slice(context);

    hkdf.expand(&hkdf_label, &mut okm);
    okm
}

pub(crate) fn compute_output_key_and_tag(secret: &[u8], context: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let hkdf = HkdfSha256::new(None, &secret);
    let output_key = compute_hkdf(&hkdf, STR_SESSION_KEY, context);
    let handshake_secret = compute_hkdf(&hkdf, STR_HANDSHAKE_SECRET, context);

    let handshake_hkdf = HkdfSha256::from_prk(&handshake_secret).unwrap();
    let verify_tag_client = compute_hkdf(&handshake_hkdf, STR_CLIENT_MAC, b"");
    let verify_tag_server = compute_hkdf(&handshake_hkdf, STR_SERVER_MAC, b"");

    (output_key, verify_tag_client, verify_tag_server)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn try_hash() {
        let result = hash(b"test");
        println!("{:?}", result);
    }

    #[test]
    fn try_compute_output_key_and_tag() {
        let (key, t1, t2) = compute_output_key_and_tag(b"daiuwdhawuidhiuwad", b"");

        println!("{:?}", key);
        println!("{:?}", t1);
        println!("{:?}", t2);
    }
}