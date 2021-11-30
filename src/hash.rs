use sha3::{Sha3_256, Digest};

pub(crate) fn hash(data: &[u8]) -> [u8; 32] { // TODO use or remove
    <[u8; 32]>::from(Sha3_256::digest(data)) // TODO hardcoded [u8; 32] for sha256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash() {
        let result = hash(b"test");
        println!("{:?}", result);
    }
}