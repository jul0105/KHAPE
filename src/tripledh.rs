use std::convert::TryFrom;

use sha3::{Digest, Sha3_256};

use crate::alias::{PrivateKey, PublicKey, OutputKey, VerifyTag};
use crate::group::compute_shared_key;
use crate::key_derivation;
use hkdf::Hkdf;

#[derive(Debug, PartialEq)]
pub struct KeyExchangeOutput {
    pub(crate) output_key: OutputKey,
    pub(crate) client_verify_tag: VerifyTag,
    pub(crate) server_verify_tag: VerifyTag
}

pub(crate) fn compute_client(pub_b: PublicKey, pub_y: PublicKey, priv_a: PrivateKey, priv_x: PrivateKey) -> KeyExchangeOutput {
    // B^x || Y^a || Y^x
    let o_client = [
        compute_shared_key(priv_x, pub_b).to_bytes(),
        compute_shared_key(priv_a, pub_y).to_bytes(),
        compute_shared_key(priv_x, pub_y).to_bytes()
    ].concat();

    key_derivation::compute_output_key_and_tag(&o_client, b"")
}

pub(crate) fn compute_server(pub_a: PublicKey, pub_x: PublicKey, priv_b: PrivateKey, priv_y: PrivateKey) -> KeyExchangeOutput {
    // X^b || A^y || X^y
    let o_server = [
        compute_shared_key(priv_b, pub_x).to_bytes(),
        compute_shared_key(priv_y, pub_a).to_bytes(),
        compute_shared_key(priv_y, pub_x).to_bytes()
    ].concat();

    key_derivation::compute_output_key_and_tag(&o_server, b"")
}


#[cfg(test)]
mod tests {
    use crate::group::generate_keys;

    use super::*;

    #[test]
    fn test_tripledh() {
        // Client
        let (priv_a, pub_a) = generate_keys();
        let (priv_x, pub_x) = generate_keys();

        // Server
        let (priv_b, pub_b) = generate_keys();
        let (priv_y, pub_y) = generate_keys();

        let k1 = compute_client(pub_b, pub_y, priv_a, priv_x);
        let k2 = compute_server(pub_a, pub_x, priv_b, priv_y);

        assert_eq!(k1, k2);
    }
}