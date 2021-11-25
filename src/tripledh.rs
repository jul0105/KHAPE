use crate::group::compute_shared_key;
use sha3::{Sha3_256, Digest};
use crate::khape::{CurvePoint, CurveScalar};
use std::convert::TryFrom;

pub fn compute_client(B: CurvePoint, Y: CurvePoint, a: CurveScalar, x: CurveScalar) -> [u8; 32] {
    // B^x || Y^a || Y^x
    let o_client_1 = compute_shared_key(x.to_bytes(), B.to_bytes());
    let o_client_2 = compute_shared_key(a.to_bytes(), Y.to_bytes());
    let o_client_3 = compute_shared_key(x.to_bytes(), Y.to_bytes());
    let o_client = [o_client_1, o_client_2, o_client_3].concat();

    <[u8; 32]>::try_from(Sha3_256::digest(&o_client).to_vec()).unwrap() // TODO sid, C, S ?
}

pub fn compute_server(A: CurvePoint, X: CurvePoint, b: CurveScalar, y: CurveScalar) -> [u8; 32] {
    // X^b || A^y || X^y
    let o_server_1 = compute_shared_key(b.to_bytes(), X.to_bytes());
    let o_server_2 = compute_shared_key(y.to_bytes(), A.to_bytes());
    let o_server_3 = compute_shared_key(y.to_bytes(), X.to_bytes());
    let o_server = [o_server_1, o_server_2, o_server_3].concat();

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