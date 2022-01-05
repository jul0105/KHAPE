//! Provide password hardening function with the memory-hard hashing function Argon2

use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use crate::alias::{DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_T_COST, DEFAULT_ARGON2_P_COST};

/// Parameters for Argon2 strength
#[derive(Clone, Copy)]
pub struct SlowHashParams {
    pub m_cost: u32,
    pub t_cost: u32,
    pub p_cost: u32,
}

impl Default for SlowHashParams {
    fn default() -> Self {
        SlowHashParams {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST
        }
    }
}

/// Harden input with the memory-hard hashing function Argon2
pub(crate) fn hash(input: &[u8], params: SlowHashParams) -> Vec<u8> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(params.m_cost, params.t_cost, params.p_cost, None).unwrap()
    );

    let salt = SaltString::b64_encode(&[0u8; argon2::MIN_SALT_LEN]).unwrap();
    argon2.hash_password(input, &salt).unwrap().to_string().into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2() {
        let result = hash(b"test", SlowHashParams::default());
        println!("{:?}", result);
    }

    #[test]
    fn try_argon2() {
        let input = b"daiuhwduiahwuid";
        // Argon2 with default params (Argon2id v19)
        let argon2 = Argon2::default();

        // Hash password to PHC string ($argon2id$v=19$...)
        let salt = SaltString::b64_encode(&[0u8; argon2::MIN_SALT_LEN]).unwrap();
        let result = argon2.hash_password(input, &salt).unwrap().to_string();
        println!("{}", result);
        println!("{:?}", result.into_bytes());
    }
}