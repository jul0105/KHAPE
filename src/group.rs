use curve25519_dalek::constants::X25519_BASEPOINT;
use curve25519_dalek::montgomery::{elligator_decode, elligator_encode};
use curve25519_dalek::scalar::Scalar;
use rand::{Rng, thread_rng};

use crate::alias::{PrivateKey, PublicKey, RawPublicKey, SharedKey};

const SIGN: u8 = 0; // TODO elligator sign

fn compute_public_key(private_key: PrivateKey) -> RawPublicKey {
    X25519_BASEPOINT * private_key
}

pub(crate) fn compute_shared_key(own_private_key: PrivateKey, opposing_public_key: PublicKey) -> SharedKey {
    own_private_key * encode_public_key(&opposing_public_key)
}

/// Randomly generate a private key using the rejection method
/// If the value generated doesn't fit. Generate a new random value and test it again.
fn generate_private_key() -> PrivateKey {
    loop {
        let private_key_candidate = Scalar::from_bits(thread_rng().gen::<[u8; 32]>());
        if private_key_candidate == private_key_candidate.reduce() {
            return private_key_candidate;
        }
    }
}

pub(crate) fn generate_keys() -> (PrivateKey, PublicKey) {
    loop {
        let private_key = generate_private_key();
        let public_key = compute_public_key(private_key);
        let result = decode_public_key(&public_key);
        if result.is_some() {
            return (private_key, result.unwrap())
        }
    }
}

fn decode_public_key(point: &RawPublicKey) -> Option<PublicKey> {
    elligator_decode(point, SIGN.into())
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

    #[test]
    fn bench_generate_private_key() {
        let mut sum = 0;
        for _ in 0..100 {
            let mut i = 0;
            loop {
                let private_key_candidate = Scalar::from_canonical_bytes(thread_rng().gen::<[u8; 32]>());
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
    fn bench_generate_private_key_2() {
        let mut sum = 0;
        for _ in 0..100 {
            let mut i = 0;
            loop {
                let private_key_candidate = Scalar::from_bits(thread_rng().gen::<[u8; 32]>());
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