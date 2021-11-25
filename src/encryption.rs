use curve25519_dalek::montgomery::MontgomeryPoint;
use serde::{Deserialize, Serialize};

use crate::khape::{CurvePoint, CurveScalar};

pub struct Envelope {
    pub a: CurveScalar,
    pub B: CurvePoint,
}

// Serialize (sends, store)
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct EncryptedEnvelope {
    pub a: [u8; 32],
    pub B: [u8; 32],
}

impl Envelope {
    pub fn encrypt(&self) -> EncryptedEnvelope {
        EncryptedEnvelope {
            a: self.a.to_bytes(),
            B: self.B.to_bytes()
        }
    }
}

impl EncryptedEnvelope {
    pub fn decrypt(&self) -> Envelope {
        Envelope {
            a: CurveScalar::from_bits(self.a),
            B: MontgomeryPoint(self.B),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::generate_keys;

    #[test]
    fn test_encrypt_decrypt() {
        let (a, B) = generate_keys();
        let envelope = Envelope {
            a,
            B,
        };

        let encrypted_envelope = envelope.encrypt();
        let envelope2 = encrypted_envelope.decrypt();
        assert_eq!(a, envelope2.a);
        assert_eq!(B, envelope2.B);

    }
}