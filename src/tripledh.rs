use std::convert::TryFrom;

use sha3::{Digest, Sha3_256};

use crate::alias::{PrivateKey, PublicKey, OutputKey, VerifyTag};
use crate::group::compute_shared_key;
use crate::hash;
use hkdf::Hkdf;

pub(crate) fn compute_client(pub_b: PublicKey, pub_y: PublicKey, priv_a: PrivateKey, priv_x: PrivateKey) -> [u8; 32] {
    // B^x || Y^a || Y^x
    let o_client = [
        compute_shared_key(priv_x, pub_b).to_bytes(),
        compute_shared_key(priv_a, pub_y).to_bytes(),
        compute_shared_key(priv_x, pub_y).to_bytes()
    ].concat();

    <[u8; 32]>::try_from(Sha3_256::digest(&o_client).to_vec()).unwrap() // TODO sid, C, S ?
}

pub(crate) fn compute_server(pub_a: PublicKey, pub_x: PublicKey, priv_b: PrivateKey, priv_y: PrivateKey) -> [u8; 32] {
    // X^b || A^y || X^y
    let o_server = [
        compute_shared_key(priv_b, pub_x).to_bytes(),
        compute_shared_key(priv_y, pub_a).to_bytes(),
        compute_shared_key(priv_y, pub_x).to_bytes()
    ].concat();

    <[u8; 32]>::try_from(Sha3_256::digest(&o_server).to_vec()).unwrap() // TODO sid, C, S ?
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