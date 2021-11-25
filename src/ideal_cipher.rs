use sha3::{Sha3_256, Digest};
use std::convert::TryFrom;

const INPUT_SIZE: usize = 64;
const PART_SIZE: usize = INPUT_SIZE/2;
const NB_FEISTEL_ROUND: usize = 14;


pub fn encrypt_feistel(key: [u8; 32], plaintext: [u8; INPUT_SIZE]) -> [u8; INPUT_SIZE] {
    // Split plaintext in 2 equal part L0 and R0
    let mut left_part: [u8; 32] = <[u8; 32]>::try_from(&plaintext[0..32]).unwrap();
    let mut right_part: [u8; 32] = <[u8; 32]>::try_from(&plaintext[32..64]).unwrap();

    // N-1 feistel round
    for i in 0..(NB_FEISTEL_ROUND - 1) {
        let result = feistel_round(key, [i as u8], left_part, right_part);
        left_part = right_part;
        right_part = result;
    }

    // Final round (without mix)
    left_part = feistel_round(key, [(NB_FEISTEL_ROUND - 1) as u8], left_part, right_part);

    <[u8; 64]>::try_from([left_part, right_part].concat()).unwrap()
}

pub fn decrypt_feistel(key: [u8; 32], ciphertext: [u8; INPUT_SIZE]) -> [u8; INPUT_SIZE] {
    // Split plaintext in 2 equal part Ln+1 and Rn+1
    let mut right_part: [u8; 32] = <[u8; 32]>::try_from(&ciphertext[0..32]).unwrap();
    let mut left_part: [u8; 32] = <[u8; 32]>::try_from(&ciphertext[32..64]).unwrap();

    // N-1 feistel round
    for i in (1..NB_FEISTEL_ROUND).rev() {
        let result = feistel_round(key, [i as u8], right_part, left_part);
        right_part = left_part;
        left_part = result;
    }

    // Final round (without mix)
    right_part = feistel_round(key, [0u8], right_part, left_part);

    <[u8; 64]>::try_from([left_part, right_part].concat()).unwrap()
}

fn feistel_round(key: [u8; 32], round_nb: [u8; 1], left_part: [u8; 32], right_part: [u8; 32]) -> [u8; 32] {
    let hash_result: [u8; 32] = <[u8; 32]>::from(Sha3_256::new()
        .chain(key)
        .chain(round_nb)
        .chain(right_part)
        .finalize());
    let result: Vec<u8> = left_part.iter().zip(hash_result.iter()).map(|(&a, &b)| a ^ b).collect();
    <[u8; 32]>::try_from(result).unwrap()
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = [1u8; 64];
        let key = [2u8; 32];

        let ciphertext = encrypt_feistel(key, plaintext);

        let plaintext2 = decrypt_feistel(key, ciphertext);

        assert_eq!(plaintext, plaintext2);
    }
}