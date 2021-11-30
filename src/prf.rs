use sha3::Sha3_256;
use hmac::{Hmac, Mac, NewMac};

type HmacSha256 = Hmac<Sha3_256>;

pub(crate) fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    // Create HMAC-SHA256 instance which implements `Mac` trait
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);

    // `result` has type `Output` which is a thin wrapper around array of
    // bytes for providing constant time equality check
    let result = mac.finalize();

    // To get underlying array use `into_bytes` method, but be careful, since
    // incorrect use of the code value may permit timing attacks which defeat
    // the security provided by the `Output`
    <[u8; 32]>::from(result.into_bytes()) // TODO hardcoded [u8; 32] for sha256
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hmac() {
        let result = hmac(b"key", b"data");
        println!("{:?}", result)
    }
}