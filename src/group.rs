use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::montgomery::{MontgomeryPoint, elligator_decode, elligator_encode};
use curve25519_dalek::constants::{ED25519_BASEPOINT_TABLE, X25519_BASEPOINT};
use rand::{thread_rng, Rng};
use curve25519_dalek::field::FieldElement;
use crate::khape::{PublicKey, PrivateKey, RawPublicKey, SharedKey};

const SIGN: u8 = 0; // TODO elligator sign

fn compute_public_key(private_key: PrivateKey) -> RawPublicKey {
    X25519_BASEPOINT * private_key
}

pub fn compute_shared_key(own_private_key: PrivateKey, opposing_public_key: PublicKey) -> SharedKey {
    (own_private_key * encode_public_key(&opposing_public_key))
}

fn generate_private_key() -> PrivateKey {
    loop {
        let private_key_candidate = Scalar::from_canonical_bytes(thread_rng().gen::<[u8; 32]>());
        if private_key_candidate.is_some() {
            return private_key_candidate.unwrap();
        }
    }
}

pub fn generate_keys() -> (PrivateKey, PublicKey) { // TODO try to return FieldElement instead of [u8; 32]
    loop {
        let private_key = generate_private_key();
        let public_key = compute_public_key(private_key);
        let result = elligator_decode(&public_key, SIGN.into());
        if result.is_some() {
            return (private_key, result.unwrap())
        }
    }
}

fn decode_public_key(point: &RawPublicKey) -> PublicKey {
    elligator_decode(point, SIGN.into()).unwrap()
}
fn encode_public_key(field_element: &PublicKey) -> RawPublicKey {
    elligator_encode(field_element)
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

    #[test]
    fn test_generate_private_key_with_rejection_method() {
        for i in 0..1000 {
            let random_bytes = thread_rng().gen::<[u8; 32]>();
            let a = Scalar::from_canonical_bytes(random_bytes);
            if a.is_some() {
                println!("Success on try {}", i);
                return;
            } else {
                println!("try {}", i);
            }
        }
    }
}