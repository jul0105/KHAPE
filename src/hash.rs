use sha3::{Sha3_256, Digest};

pub(crate) fn hash(data: &[u8]) -> [u8; 32] { // TODO use or remove
    <[u8; 32]>::from(Sha3_256::digest(data)) // TODO hardcoded [u8; 32] for sha256
}

pub(crate) fn slow_hash(content: Vec<u8>) -> Vec<u8> {
    unimplemented!();
}

pub(crate) fn hkdf_envelope_key(content: Vec<u8>, content2: Vec<u8>) -> Vec<u8> {
    unimplemented!();
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