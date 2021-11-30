use serde::{Deserialize, Serialize};

use crate::khape::{PublicKey, PrivateKey};
use std::convert::TryFrom;
use crate::ideal_cipher::{encrypt_feistel, decrypt_feistel};
use serde_big_array::BigArray;

pub struct Envelope {
    pub a: PrivateKey,
    pub B: PublicKey,
}

// Serialize (sends, store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedEnvelope {
    #[serde(with = "BigArray")]
    pub ciphertext: [u8; 64],
}

impl Envelope {
    pub fn encrypt(&self, key: [u8; 32]) -> EncryptedEnvelope {
        let plaintext = <[u8; 64]>::try_from([self.a.to_bytes(), self.B.to_bytes()].concat()).unwrap();
        let ciphertext = encrypt_feistel(key, plaintext);

        EncryptedEnvelope {
            ciphertext,
        }
    }
}

impl EncryptedEnvelope {
    pub fn decrypt(&self, key: [u8; 32]) -> Envelope {
        let plaintext = decrypt_feistel(key, self.ciphertext);
        let left_part: [u8; 32] = <[u8; 32]>::try_from(&plaintext[0..32]).unwrap();
        let right_part: [u8; 32] = <[u8; 32]>::try_from(&plaintext[32..64]).unwrap();

        Envelope {
            a: PrivateKey::from_bits(left_part),
            B: PublicKey::from_bytes(&right_part),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::generate_keys;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1u8; 32];

        let (a, B) = generate_keys();
        let envelope = Envelope {
            a,
            B,
        };

        let encrypted_envelope = envelope.encrypt(key);
        let envelope2 = encrypted_envelope.decrypt(key);

        println!("a1 : {:?}", a);
        println!("B1 : {:?}", B);
        println!("a2 : {:?}", envelope2.a);
        println!("B2 : {:?}", envelope2.B);

        assert_eq!(a, envelope2.a);
        assert_eq!(B, envelope2.B);

    }
}