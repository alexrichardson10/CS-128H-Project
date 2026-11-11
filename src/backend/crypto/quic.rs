use crate::backend::crypto::hkdf::{hkdf_expand_label, hkdf_extract};

pub struct KeySet {
    pub key: Vec<u8>, // aead
    pub iv: Vec<u8>, // initialization vector
    pub hp: Vec<u8>, // header protection
}

impl KeySet {
    pub fn new(ikm: &Vec<u8>) -> KeySet {
        let key: Vec<u8> = hkdf_expand_label(
            ikm,
            String::from("quic key"),
            &Vec::new(),
            16u16
        );

        let iv: Vec<u8> = hkdf_expand_label(
            ikm,
            String::from("quic iv"),
            &Vec::new(),
            12u16
        );

        let hp: Vec<u8> = hkdf_expand_label(
            ikm,
            String::from("quic hp"),
            &Vec::new(),
            16u16
        );

        KeySet { key, iv, hp }
    }
}

#[derive(Default)]
pub struct QuicKeySchedule {
    // Initial keys, derived from destination connection id
    pub initial_secret: Option<Vec<u8>>,
    pub client_initial_secret: Option<Vec<u8>>,
    pub server_initial_secret: Option<Vec<u8>>,

    // keys for encrypting the initial packets
    pub client_initial_keys: Option<KeySet>,
    pub server_initial_keys: Option<KeySet>,
}

impl QuicKeySchedule {
    pub fn new() -> QuicKeySchedule {
        QuicKeySchedule::default()
    }

    pub fn from(client_dst_connection_id: &Vec<u8>) -> QuicKeySchedule {
        let mut result: QuicKeySchedule = QuicKeySchedule::new();
        result.generate_initial_secrets(client_dst_connection_id);
        
        result
    }

    pub fn generate_initial_secrets(&mut self, client_dst_connection_id: &Vec<u8>) {
        let initial_salt: Vec<u8> = hex::decode(
            "38762cf7f55934b34d179ae6a4c80cadccbb7f0a").unwrap();

        self.initial_secret = Some(hkdf_extract(
            &initial_salt,
            client_dst_connection_id
        ));

        self.client_initial_secret = Some(hkdf_expand_label(
            self.initial_secret.as_ref().unwrap(),
            String::from("client in"),
            &Vec::new(),
            32u16
        ));

        self.server_initial_secret = Some(hkdf_expand_label(
            self.initial_secret.as_ref().unwrap(),
            String::from("server in"),
            &Vec::new(),
            32u16
        ));
        
        self.client_initial_keys = Some(KeySet::new(
            &self.client_initial_secret.as_ref().unwrap(),
        ));

        self.server_initial_keys = Some(KeySet::new(
            &self.server_initial_secret.as_ref().unwrap(),
        ));
    }
}