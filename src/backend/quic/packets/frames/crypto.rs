use crate::backend::quic::packets::utils::decode_variable_length_integer;

pub enum HandshakeType {
    ClientHello = 1,
    ServerHello = 2,
    NewSessionTicket = 4,
    EndOfEarlyData = 5,
    EncryptedExtensions = 8,
    Certificate = 11,
    CertificateRequest = 13,
    CertificateVerify = 15,
    Finished = 20,
    KeyUpdate = 24,
    MessageHash = 254
}

#[derive(Debug, Clone)]
pub struct Crypto {
    pub offset: u64, // variable length integer
    pub length: u64, // also a variable length integer
    pub crypto_data: Vec<u8>,
}

impl Crypto {
    pub fn new(data: &Vec<u8>, position: &mut usize) -> Crypto {
        *position += 1;

        let (offset_bytes, offset) =
            decode_variable_length_integer(&data[(*position)..].to_vec()).unwrap();

        *position += offset_bytes as usize;

        let (length_bytes, length) =
            decode_variable_length_integer(&data[(*position)..].to_vec()).unwrap();

        *position += length_bytes as usize;

        let crypto_data: Vec<u8> = data[*position..(*position + length as usize)].to_vec();

        *position += length as usize;

        Crypto {
            offset,
            length,
            crypto_data,
        }
    }
}