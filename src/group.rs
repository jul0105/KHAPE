use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, X25519_BASEPOINT};
use rand::{thread_rng, Rng};

pub fn compute_private_key(bytes: [u8; 32]) -> Scalar {
    clamp_scalar(bytes)
}

pub fn compute_public_key(private_key: Scalar) -> MontgomeryPoint {
    X25519_BASEPOINT * private_key
}

pub fn compute_shared_key(own_private_key: [u8; 32], opposing_public_key: [u8; 32]) -> [u8; 32] {
    (clamp_scalar(own_private_key) * MontgomeryPoint(opposing_public_key)).to_bytes() // From x25519-dalek library
}

pub fn generate_private_key() -> Scalar {
    clamp_scalar(thread_rng().gen::<[u8; 32]>())
}

pub fn generate_keys() -> (Scalar, MontgomeryPoint) {
    let private_key = generate_private_key();
    (private_key, compute_public_key(private_key))
}


fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar { // From x25519-dalek library
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}