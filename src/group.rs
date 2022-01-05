//! Provide group operation functions on elliptic curve

use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::{elligator_decode, elligator_encode};
use curve25519_dalek::scalar::Scalar;
use rand::{Rng, thread_rng};

use crate::alias::{PrivateKey, PublicKey, RawPublicKey, SharedKey, KEY_SIZE};

const ELLIGATOR_SIGN: u8 = 0;

#[cfg(feature = "bench")]
pub fn compute_shared_key_pub(own_private_key: PrivateKey, opposing_public_key: PublicKey) -> SharedKey {
    compute_shared_key(own_private_key, opposing_public_key)
}

#[cfg(feature = "bench")]
pub fn generate_keys_pub() -> (PrivateKey, PublicKey) {
    generate_keys()
}


fn compute_public_key(private_key: PrivateKey) -> RawPublicKey {
    X25519_BASEPOINT * private_key
}

/// Compute the exponentiation to return the DH shared key
pub(crate) fn compute_shared_key(own_private_key: PrivateKey, opposing_public_key: PublicKey) -> SharedKey {
    own_private_key * encode_public_key(&opposing_public_key)
}

/// Randomly generate a private key using the rejection method
/// If the value generated doesn't fit. Generate a new random value and test it again.
fn generate_private_key() -> PrivateKey {
    loop {
        let private_key_candidate = Scalar::from_bits(thread_rng().gen::<[u8; KEY_SIZE]>());
        if private_key_candidate == private_key_candidate.reduce() {
            return private_key_candidate;
        }
    }
}

/// Randomly generates a new key pair and decode the public key using the Elligator2 map.
pub(crate) fn generate_keys() -> (PrivateKey, PublicKey) {
    loop {
        let private_key = generate_private_key();
        let public_key = compute_public_key(private_key);
        let result = decode_public_key(&public_key);
        if let Some(field_element) = result {
            return (private_key, field_element);
        }
    }
}

fn decode_public_key(point: &RawPublicKey) -> Option<PublicKey> {
    elligator_decode(point, ELLIGATOR_SIGN.into())
}
fn encode_public_key(field_element: &PublicKey) -> RawPublicKey {
    elligator_encode(field_element)
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_with_elligator() {
        let (_, public_key_elligator) = generate_keys();
        let public_key = encode_public_key(&public_key_elligator);
        let public_key_elligator2 = decode_public_key(&public_key).unwrap();

        assert_eq!(public_key_elligator, public_key_elligator2);
    }

    #[test]
    fn test_compute_public_key() {
        let private_key_1 = Scalar::from_bits([1u8; KEY_SIZE]);
        let private_key_2 = Scalar::from_bits([2u8; KEY_SIZE]);
        assert_ne!(private_key_1, private_key_2);

        let pub_key_1 = compute_public_key(private_key_1);
        let pub_key_2 = compute_public_key(private_key_2);

        assert_ne!(pub_key_1, pub_key_2)
    }

    #[test]
    fn test_compute_dh() {
        let (priv_a, pub_a) = generate_keys();
        let (priv_b, pub_b) = generate_keys();
        assert_ne!(priv_a, priv_b);
        assert_ne!(pub_a, pub_b);

        let k1 = compute_shared_key(priv_a, pub_b);
        let k2 = compute_shared_key(priv_b, pub_a);
        assert_eq!(k1, k2)
    }

    #[test]
    fn bench_generate_private_key_with_rejection_method() {
        let mut sum = 0;
        for _ in 0..100 {
            let mut i = 0;
            loop {
                let private_key_candidate = Scalar::from_canonical_bytes(thread_rng().gen::<[u8; KEY_SIZE]>());
                if private_key_candidate.is_some() {
                    println!("succes after {} tries", i);
                    break;
                }
                i += 1;
            }
            sum += i;
        }

        println!("Average {}", (sum as f32)/100f32)
    }

    #[test]
    fn bench_generate_private_key_with_rejection_method_2() {
        let mut sum = 0;
        for _ in 0..1000 {
            let mut i = 0;
            loop {
                let private_key_candidate = Scalar::from_bits(thread_rng().gen::<[u8; KEY_SIZE]>());
                if private_key_candidate == private_key_candidate.reduce() {
                    println!("succes after {} tries", i);
                    break;
                }
                i += 1;
            }
            sum += i;
        }

        println!("Average {}", (sum as f32)/100f32)
    }
}