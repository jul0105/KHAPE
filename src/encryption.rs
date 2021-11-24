use crate::khape::{Envelope, EncryptedEnvelope, CurveScalar, CurvePoint};
use curve25519_dalek::montgomery::MontgomeryPoint;

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