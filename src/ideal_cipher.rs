//! Feistel cipher scheme implementation that is indistinguishable from an ideal cipher

use sha3::{Sha3_256, Digest};
use std::convert::TryFrom;
use crate::alias::{KEY_SIZE, FEISTEL_CIPHER_SIZE, FEISTEL_PART_SIZE};

const NB_FEISTEL_ROUND: usize = 14;

#[cfg(feature = "bench")]
pub fn encrypt_feistel_pub(key: [u8; KEY_SIZE], plaintext: [u8; FEISTEL_CIPHER_SIZE]) -> [u8; FEISTEL_CIPHER_SIZE] {
    encrypt_feistel(key, plaintext)
}

#[cfg(feature = "bench")]
pub fn decrypt_feistel_pub(key: [u8; KEY_SIZE], ciphertext: [u8; FEISTEL_CIPHER_SIZE]) -> [u8; FEISTEL_CIPHER_SIZE] {
    decrypt_feistel(key, ciphertext)
}

/// Compute the 14-round Feistel cipher to encrypt
pub(crate) fn encrypt_feistel(key: [u8; KEY_SIZE], plaintext: [u8; FEISTEL_CIPHER_SIZE]) -> [u8; FEISTEL_CIPHER_SIZE] {
    // Split plaintext in 2 equal part L0 and R0
    let mut left_part: [u8; FEISTEL_PART_SIZE] = <[u8; FEISTEL_PART_SIZE]>::try_from(&plaintext[0..FEISTEL_PART_SIZE]).unwrap();
    let mut right_part: [u8; FEISTEL_PART_SIZE] = <[u8; FEISTEL_PART_SIZE]>::try_from(&plaintext[FEISTEL_PART_SIZE..FEISTEL_CIPHER_SIZE]).unwrap();

    // N-1 feistel round
    for i in 0..(NB_FEISTEL_ROUND - 1) {
        let result = feistel_round(key, [i as u8], left_part, right_part);
        left_part = right_part;
        right_part = result;
    }

    // Final round (without mix)
    left_part = feistel_round(key, [(NB_FEISTEL_ROUND - 1) as u8], left_part, right_part);

    <[u8; FEISTEL_CIPHER_SIZE]>::try_from([left_part, right_part].concat()).unwrap()
}

/// Compute the 14-round Feistel cipher to decrypt
pub(crate) fn decrypt_feistel(key: [u8; KEY_SIZE], ciphertext: [u8; FEISTEL_CIPHER_SIZE]) -> [u8; FEISTEL_CIPHER_SIZE] {
    // Split plaintext in 2 equal part Ln+1 and Rn+1
    let mut right_part: [u8; FEISTEL_PART_SIZE] = <[u8; FEISTEL_PART_SIZE]>::try_from(&ciphertext[0..FEISTEL_PART_SIZE]).unwrap();
    let mut left_part: [u8; FEISTEL_PART_SIZE] = <[u8; FEISTEL_PART_SIZE]>::try_from(&ciphertext[FEISTEL_PART_SIZE..FEISTEL_CIPHER_SIZE]).unwrap();

    // N-1 feistel round
    for i in (1..NB_FEISTEL_ROUND).rev() {
        let result = feistel_round(key, [i as u8], right_part, left_part);
        right_part = left_part;
        left_part = result;
    }

    // Final round (without mix)
    right_part = feistel_round(key, [0u8], right_part, left_part);

    <[u8; FEISTEL_CIPHER_SIZE]>::try_from([right_part, left_part].concat()).unwrap()
}

/// Individual Feistel round
fn feistel_round(key: [u8; KEY_SIZE], round_nb: [u8; 1], left_part: [u8; FEISTEL_PART_SIZE], right_part: [u8; FEISTEL_PART_SIZE]) -> [u8; FEISTEL_PART_SIZE] {
    let hash_result: [u8; FEISTEL_PART_SIZE] = <[u8; FEISTEL_PART_SIZE]>::from(Sha3_256::new()
        .chain(key)
        .chain(round_nb)
        .chain(right_part)
        .finalize());
    let result: Vec<u8> = left_part.iter().zip(hash_result.iter()).map(|(&a, &b)| a ^ b).collect();
    <[u8; FEISTEL_PART_SIZE]>::try_from(result).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = [189, 206, 64, 10, 51, 196, 203, 62, 105, 37, 166, 237, 79, 135, 252, 150, 218, 250, 110, 164, 152, 156, 103, 156, 56, 193, 184, 151, 62, 156, 211, 199, 220, 249, 70, 200, 28, 188, 9, 7, 60, 182, 247, 218, 96, 131, 73, 205, 149, 39, 75, 246, 45, 113, 6, 134, 165, 66, 31, 58, 148, 142, 242, 197];
        let key = [2u8; 32];

        let ciphertext = encrypt_feistel(key, plaintext);

        let plaintext2 = decrypt_feistel(key, ciphertext);

        println!("plaintext1 : {:?}", plaintext);
        println!("ciphertext : {:?}", ciphertext);
        println!("plaintext2 : {:?}", plaintext2);

        assert_eq!(plaintext, plaintext2);
    }

    #[test]
    fn test_encrypt_decrypt_with_wront_key() {
        let plaintext = [189, 206, 64, 10, 51, 196, 203, 62, 105, 37, 166, 237, 79, 135, 252, 150, 218, 250, 110, 164, 152, 156, 103, 156, 56, 193, 184, 151, 62, 156, 211, 199, 220, 249, 70, 200, 28, 188, 9, 7, 60, 182, 247, 218, 96, 131, 73, 205, 149, 39, 75, 246, 45, 113, 6, 134, 165, 66, 31, 58, 148, 142, 242, 197];
        let key1 = [2u8; 32];
        let key2 = [3u8; 32];

        let ciphertext = encrypt_feistel(key1, plaintext);

        let plaintext2 = decrypt_feistel(key2, ciphertext);

        println!("plaintext1 : {:?}", plaintext);
        println!("ciphertext : {:?}", ciphertext);
        println!("plaintext2 : {:?}", plaintext2);

        assert_ne!(plaintext, plaintext2);
    }

    #[test]
    fn test_decrypt_encrypt() {
        let ciphertext = [189, 206, 64, 10, 51, 196, 203, 62, 105, 37, 166, 237, 79, 135, 252, 150, 218, 250, 110, 164, 152, 156, 103, 156, 56, 193, 184, 151, 62, 156, 211, 199, 220, 249, 70, 200, 28, 188, 9, 7, 60, 182, 247, 218, 96, 131, 73, 205, 149, 39, 75, 246, 45, 113, 6, 134, 165, 66, 31, 58, 148, 142, 242, 197];
        let key = [2u8; 32];

        let plaintext = decrypt_feistel(key, ciphertext);

        let ciphertext2 = encrypt_feistel(key, plaintext);

        println!("ciphertext : {:?}", ciphertext);
        println!("plaintext : {:?}", plaintext);
        println!("ciphertext2 : {:?}", ciphertext2);

        assert_eq!(ciphertext, ciphertext2);
    }

    #[test]
    fn test_decrypt_encrypt_with_wrong_key() {
        let ciphertext = [189, 206, 64, 10, 51, 196, 203, 62, 105, 37, 166, 237, 79, 135, 252, 150, 218, 250, 110, 164, 152, 156, 103, 156, 56, 193, 184, 151, 62, 156, 211, 199, 220, 249, 70, 200, 28, 188, 9, 7, 60, 182, 247, 218, 96, 131, 73, 205, 149, 39, 75, 246, 45, 113, 6, 134, 165, 66, 31, 58, 148, 142, 242, 197];
        let key1 = [2u8; 32];
        let key2 = [3u8; 32];

        let plaintext = decrypt_feistel(key1, ciphertext);

        let ciphertext2 = encrypt_feistel(key2, plaintext);

        println!("ciphertext : {:?}", ciphertext);
        println!("plaintext : {:?}", plaintext);
        println!("ciphertext2 : {:?}", ciphertext2);

        assert_ne!(ciphertext, ciphertext2);
    }

    #[test]
    fn test_double_encrypt() {
        let plaintext = [189, 206, 64, 10, 51, 196, 203, 62, 105, 37, 166, 237, 79, 135, 252, 150, 218, 250, 110, 164, 152, 156, 103, 156, 56, 193, 184, 151, 62, 156, 211, 199, 220, 249, 70, 200, 28, 188, 9, 7, 60, 182, 247, 218, 96, 131, 73, 205, 149, 39, 75, 246, 45, 113, 6, 134, 165, 66, 31, 58, 148, 142, 242, 197];
        let key = [2u8; 32];

        let ciphertext = encrypt_feistel(key, plaintext);

        let ciphertext2 = encrypt_feistel(key, ciphertext);

        println!("plaintext : {:?}", plaintext);
        println!("ciphertext : {:?}", ciphertext);
        println!("ciphertext2 : {:?}", ciphertext2);

        assert_ne!(plaintext, ciphertext2);
    }
}