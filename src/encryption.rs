use std::convert::TryFrom;

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::alias::{PrivateKey, PublicKey};
use crate::ideal_cipher::{decrypt_feistel, encrypt_feistel};

pub(crate) struct Envelope {
    pub(crate) priv_a: PrivateKey,
    pub(crate) pub_b: PublicKey,
}

// Serialize (sends, store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedEnvelope {
    #[serde(with = "BigArray")]
    ciphertext: [u8; 64],
}

impl Envelope {
    pub(crate) fn encrypt(&self, key: [u8; 32]) -> EncryptedEnvelope {
        let plaintext = <[u8; 64]>::try_from([self.priv_a.to_bytes(), self.pub_b.to_bytes()].concat()).unwrap();
        let ciphertext = encrypt_feistel(key, plaintext);

        EncryptedEnvelope {
            ciphertext,
        }
    }
}

impl EncryptedEnvelope {
    pub(crate) fn decrypt(&self, key: [u8; 32]) -> Envelope {
        let plaintext = decrypt_feistel(key, self.ciphertext);
        let left_part: [u8; 32] = <[u8; 32]>::try_from(&plaintext[0..32]).unwrap();
        let right_part: [u8; 32] = <[u8; 32]>::try_from(&plaintext[32..64]).unwrap();

        Envelope {
            priv_a: PrivateKey::from_bits(left_part),
            pub_b: PublicKey::from_bytes(&right_part),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::group::generate_keys;

    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let key = [1u8; 32];

        let (priv_a, pub_b) = generate_keys();
        let envelope = Envelope {
            priv_a,
            pub_b,
        };

        let encrypted_envelope = envelope.encrypt(key);
        let envelope2 = encrypted_envelope.decrypt(key);

        println!("a1 : {:?}", priv_a);
        println!("B1 : {:?}", pub_b);
        println!("a2 : {:?}", envelope2.priv_a);
        println!("B2 : {:?}", envelope2.pub_b);

        assert_eq!(priv_a, envelope2.priv_a);
        assert_eq!(pub_b, envelope2.pub_b);

    }
}