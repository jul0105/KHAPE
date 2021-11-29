use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::montgomery::{MontgomeryPoint, elligator_decode, elligator_encode};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, X25519_BASEPOINT};
use rand::{thread_rng, Rng};
use curve25519_dalek::field::FieldElement;

const SIGN: u8 = 0; // TODO elligator sign

fn compute_private_key(bytes: [u8; 32]) -> Scalar {
    clamp_scalar(bytes)
}

fn compute_public_key(private_key: Scalar) -> MontgomeryPoint {
    X25519_BASEPOINT * private_key
}

pub fn compute_shared_key(own_private_key: [u8; 32], opposing_public_key: [u8; 32]) -> [u8; 32] {
    (clamp_scalar(own_private_key) * encode_public_key(&opposing_public_key)).to_bytes() // From x25519-dalek library
}

fn generate_private_key() -> Scalar {
    clamp_scalar(thread_rng().gen::<[u8; 32]>())
}

pub fn generate_keys() -> (Scalar, [u8; 32]) { // TODO try to return FieldElement instead of [u8; 32]
    loop {
        let private_key = generate_private_key();
        let public_key = compute_public_key(private_key);
        let result = elligator_decode(&public_key, SIGN.into());
        if result.is_some() {
            return (private_key, result.unwrap().to_bytes())
        }
    }
}

fn decode_public_key(point: &MontgomeryPoint) -> [u8; 32] {
    elligator_decode(point, SIGN.into()).unwrap().to_bytes()
}
fn encode_public_key(bytes: &[u8; 32]) -> MontgomeryPoint {
    elligator_encode(&FieldElement::from_bytes(bytes))
}

fn clamp_scalar(mut scalar: [u8; 32]) -> Scalar { // From x25519-dalek library
    scalar[0] &= 248;
    scalar[31] &= 127;
    scalar[31] |= 64;

    Scalar::from_bits(scalar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_with_elligator() {
        let (private_key, public_key_elligator) = generate_keys();
        let public_key = encode_public_key(&public_key_elligator);
        let public_key_elligator2 = decode_public_key(&public_key);

        assert_eq!(public_key_elligator, public_key_elligator2);
    }
}