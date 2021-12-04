use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

pub(crate) fn hash(input: &[u8]) -> Vec<u8> {
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(16*1024, 3, 4, None).unwrap()
    );


    let salt = SaltString::b64_encode(&[0u8; argon2::MIN_SALT_LEN]).unwrap();
    argon2.hash_password(input, &salt).unwrap().to_string().into_bytes() // TODO handle unwrap
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_argon2() {
        let result = hash(b"test");
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