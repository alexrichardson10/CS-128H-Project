use crate::backend::crypto::hkdf::{hkdf_expand_label, hkdf_extract};

#[derive(Default)]
pub struct QuicKeySchedule {
    pub initial_secret: Option<Vec<u8>>,
    pub client_initial_secret: Option<Vec<u8>>,
    pub server_initial_secret: Option<Vec<u8>>,
    pub client_key: Option<Vec<u8>>,
    pub server_key: Option<Vec<u8>>,
    pub client_iv: Option<Vec<u8>>,
    pub server_iv: Option<Vec<u8>>,
    pub client_hp_key: Option<Vec<u8>>,
    pub server_hp_key: Option<Vec<u8>>,
}

impl QuicKeySchedule {
    pub fn new() -> QuicKeySchedule {
        QuicKeySchedule::default()
    }

    pub fn generate_secrets(&mut self, client_dst_connection_id: &Vec<u8>) {
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

        self.client_key = Some(hkdf_expand_label(
            self.client_initial_secret.as_ref().unwrap(),
            String::from("quic key"),
            &Vec::new(),
            16u16
        ));

        self.server_key = Some(hkdf_expand_label(
            self.server_initial_secret.as_ref().unwrap(),
            String::from("quic key"),
            &Vec::new(),
            16u16
        ));

        self.client_iv = Some(hkdf_expand_label(
            self.client_initial_secret.as_ref().unwrap(),
            String::from("quic iv"),
            &Vec::new(),
            12u16
        ));

        self.server_iv = Some(hkdf_expand_label(
            self.server_initial_secret.as_ref().unwrap(),
            String::from("quic iv"),
            &Vec::new(),
            12u16
        ));

        self.client_hp_key = Some(hkdf_expand_label(
            self.client_initial_secret.as_ref().unwrap(),
            String::from("quic hp"),
            &Vec::new(),
            16u16
        ));

        self.server_hp_key = Some(hkdf_expand_label(
            self.server_initial_secret.as_ref().unwrap(),
            String::from("quic hp"),
            &Vec::new(),
            16u16
        ));
    }
}