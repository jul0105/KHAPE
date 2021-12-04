use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;

pub(crate) fn hash(input: &[u8]) -> Vec<u8> {
    // Argon2 with default params (Argon2id v19)
    let argon2 = Argon2::default(); // TODO setup param

    // Hash password to PHC string ($argon2id$v=19$...)
    let salt = SaltString::b64_encode(&[0u8; argon2::MIN_SALT_LEN]).unwrap();
    argon2.hash_password(input, &salt).unwrap().to_string().into_bytes() // TODO handle unwrap
}

#[cfg(test)]
mod tests {
    use super::*;

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