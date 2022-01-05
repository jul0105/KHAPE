//! Provide password hardening function with the memory-hard hashing function Argon2

use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use crate::alias::{DEFAULT_ARGON2_M_COST, DEFAULT_ARGON2_T_COST, DEFAULT_ARGON2_P_COST};

/// Parameters for Argon2 strength
#[derive(Clone, Copy, Debug, PartialEq)]
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
    fn test_slow_hash_same_input() {
        let input = b"test";

        let result1 = hash(input, SlowHashParams::default());
        let result2 = hash(input, SlowHashParams::default());
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_slow_hash_with_different_input() {
        let input1 = b"test1";
        let input2 = b"test2";
        assert_ne!(input1, input2);

        let result1 = hash(input1, SlowHashParams::default());
        let result2 = hash(input2, SlowHashParams::default());
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_slow_hash_with_same_parameters() {
        let input = b"test";
        let param1 = SlowHashParams::default();
        let param2 = SlowHashParams {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST
        };
        assert_eq!(param1, param2);

        let result1 = hash(input, param1);
        let result2 = hash(input, param2);
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_slow_hash_with_same_different_m_cost() {
        let input = b"test";
        let param1 = SlowHashParams::default();
        let param2 = SlowHashParams {
            m_cost: DEFAULT_ARGON2_M_COST + 1,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST
        };
        assert_ne!(param1, param2);

        let result1 = hash(input, param1);
        let result2 = hash(input, param2);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_slow_hash_with_same_different_t_cost() {
        let input = b"test";
        let param1 = SlowHashParams::default();
        let param2 = SlowHashParams {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST + 1,
            p_cost: DEFAULT_ARGON2_P_COST
        };
        assert_ne!(param1, param2);

        let result1 = hash(input, param1);
        let result2 = hash(input, param2);
        assert_ne!(result1, result2);
    }

    #[test]
    fn test_slow_hash_with_same_different_p_cost() {
        let input = b"test";
        let param1 = SlowHashParams::default();
        let param2 = SlowHashParams {
            m_cost: DEFAULT_ARGON2_M_COST,
            t_cost: DEFAULT_ARGON2_T_COST,
            p_cost: DEFAULT_ARGON2_P_COST + 1
        };
        assert_ne!(param1, param2);

        let result1 = hash(input, param1);
        let result2 = hash(input, param2);
        assert_ne!(result1, result2);
    }
}