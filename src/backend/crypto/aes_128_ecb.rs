use aes::Aes128;
use aes::cipher::{Array, BlockCipherEncrypt, BlockCipherDecrypt, KeyInit};

/// Encrypts one block for use in header protection.
/// key: HP
/// block: Sampled bytes
pub fn encrypt(key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&Array::from(key));

    let mut block_array = Array::from(block);
    cipher.encrypt_block(&mut block_array);

    block_array.into()
}

pub fn decrypt(key: [u8; 16], block: [u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new(&Array::from(key));

    let mut block_array = Array::from(block);
    cipher.decrypt_block(&mut block_array);

    block_array.into()
}