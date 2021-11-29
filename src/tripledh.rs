use crate::group::compute_shared_key;
use sha3::{Sha3_256, Digest};
use crate::khape::{PublicKey, PrivateKey};
use std::convert::TryFrom;

pub fn compute_client(B: PublicKey, Y: PublicKey, a: PrivateKey, x: PrivateKey) -> [u8; 32] {
    // B^x || Y^a || Y^x
    let o_client = [
        compute_shared_key(x, B).to_bytes(),
        compute_shared_key(a, Y).to_bytes(),
        compute_shared_key(x, Y).to_bytes()
    ].concat();

    <[u8; 32]>::try_from(Sha3_256::digest(&o_client).to_vec()).unwrap() // TODO sid, C, S ?
}

pub fn compute_server(A: PublicKey, X: PublicKey, b: PrivateKey, y: PrivateKey) -> [u8; 32] {
    // X^b || A^y || X^y
    let o_server = [
        compute_shared_key(b, X).to_bytes(),
        compute_shared_key(y, A).to_bytes(),
        compute_shared_key(y, X).to_bytes()
    ].concat();

    <[u8; 32]>::try_from(Sha3_256::digest(&o_server).to_vec()).unwrap() // TODO sid, C, S ?
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::generate_keys;

    #[test]
    fn test_tripledh() {
        // Client
        let (a, A) = generate_keys();
        let (x, X) = generate_keys();

        // Server
        let (b, B) = generate_keys();
        let (y, Y) = generate_keys();

        let k1 = compute_client(B, Y, a, x);
        let k2 = compute_server(A, X, b, y);

        assert_eq!(k1, k2);
    }
}