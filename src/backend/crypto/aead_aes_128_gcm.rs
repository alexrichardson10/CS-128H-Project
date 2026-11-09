//! Implementation of aead_aes_128_gcm for use in initial packet decryption/encryption

#[derive(Debug)]
pub enum AeadError {
    TooShort,
    EncryptError,
    DecryptError
}

use aes_gcm::{
    aead::{Aead, Key, KeyInit},
    Aes128Gcm, Nonce
};
use aes_gcm::aead::array::Array;
use aes_gcm::aead::consts::U12;
use aes_gcm::aead::Payload;

pub fn encrypt_with_nonce(
    server_key: &Vec<u8>,
    nonce: &Vec<u8>,
    associated_data: &Vec<u8>,
    plaintext: &Vec<u8>
) -> Result<Vec<u8>, AeadError> {
    let key = Key::<Aes128Gcm>::try_from(server_key.as_slice()).unwrap();

    let cipher = Aes128Gcm::new(&key);

    let nonce: Array<u8, U12> = Array(<[u8; 12]>::try_from(nonce.clone()).unwrap());
    let n = Nonce::try_from(nonce).unwrap();

    let payload: Payload = Payload {
        msg: plaintext,
        aad: associated_data
    };

    let result = cipher.encrypt(&n, payload);

    if result.is_ok() {
        return Ok(result.unwrap());
    }

    Err(AeadError::EncryptError)
}

/// # Parameters
/// * server_key: 16 byte vec from expand_label.
/// * packet_protection_iv: 12 byte vec from expand_label.
/// * packet_number: 8 byte vec from the packet's header. Bytes are in big-endian order.
/// * associated_data: the contents of the header from byte 1 up to and including the
///   UNPROTECTED packet number.
/// * plaintext: the packet's payload
pub fn encrypt (
    server_key: &Vec<u8>,
    packet_protection_iv: &Vec<u8>,
    packet_number: &Vec<u8>,
    associated_data: &Vec<u8>,
    plaintext: &Vec<u8>
) -> Result<Vec<u8>, AeadError> {
    let mut nonce: Vec<u8> = packet_protection_iv.clone();
    let nonce_len = nonce.len();
    for i in 0..packet_number.len() {
        nonce[nonce_len - packet_number.len() + i] ^= packet_number[i];
    }

    encrypt_with_nonce(server_key, &nonce, associated_data, plaintext)
}

pub fn decrypt (
    server_key: &Vec<u8>,
    packet_protection_iv: &Vec<u8>,
    packet_number: &Vec<u8>,
    associated_data: &Vec<u8>,
    cyphertext: &Vec<u8>
) -> Result<Vec<u8>, AeadError> {
    let mut nonce: Vec<u8> = packet_protection_iv.clone();
    let nonce_len = nonce.len();
    for i in 0..packet_number.len() {
        nonce[nonce_len - packet_number.len() + i] ^= packet_number[i];
    }

    let key = Key::<Aes128Gcm>::try_from(server_key.as_slice()).unwrap();

    let cipher = Aes128Gcm::new(&key);

    let nonce: Array<u8, U12> = Array(<[u8; 12]>::try_from(nonce.clone()).unwrap());
    let n = Nonce::try_from(nonce).unwrap();

    let payload: Payload = Payload {
        msg: cyphertext,
        aad: associated_data
    };

    let result = cipher.decrypt(&n, payload);

    if result.is_ok() {
        return Ok(result.unwrap());
    }

    Err(AeadError::DecryptError)
}