use crate::backend::crypto::hkdf::{derive_secret, hkdf_extract};
use crate::backend::crypto::diffie_hellman::{Keys};

#[derive(Default)]
pub struct KeySchedule {
    server_keys: Option<Keys>,
    early_secret: Option<Vec<u8>>,
    binder_key: Option<Vec<u8>>,
    client_early_traffic_secret: Option<Vec<u8>>,
    early_exporter_master_secret: Option<Vec<u8>>,
    handshake_secret: Option<Vec<u8>>,
    client_handshake_traffic_secret: Option<Vec<u8>>,
    server_handshake_traffic_secret: Option<Vec<u8>>,
    master_secret: Option<Vec<u8>>,
    client_application_traffic_secret_0: Option<Vec<u8>>,
    server_application_traffic_secret_0: Option<Vec<u8>>,
    exporter_master_secret: Option<Vec<u8>>,
    resumption_master_secret: Option<Vec<u8>>
}

impl KeySchedule {
    pub fn new() -> KeySchedule {
        let mut result: KeySchedule = Default::default();

        let mut zero_vec: Vec<u8> = Vec::new();
        zero_vec.resize(32, 0);

        result.server_keys = Some(Keys::new());

        result.early_secret = Some(
          hkdf_extract(
              &zero_vec,
              &zero_vec
          )
        );

        // Not important now
        /* result.binder_key = Some(
          derive_secret(
              result.early_secret.as_ref().unwrap(),
              String::from("ext binder"),
              &Vec::new()
          )
        ); */

        result
    }

    pub fn derive_handshake_secret(&mut self, client_public_key: Vec<u8>) {
        let mut zero_vec: Vec<u8> = Vec::new();
        zero_vec.resize(32, 0);

        self.handshake_secret = Some(
            hkdf_extract(
                &derive_secret(
                    self.early_secret.as_ref().unwrap(),
                    String::from("derived"),
                    &Vec::new()
                ),
                self.server_keys.as_mut().unwrap().calculate_shared_secret(client_public_key).as_ref()
            )
        );

        self.master_secret = Some(
            hkdf_extract(
                &derive_secret(
                    self.handshake_secret.as_ref().unwrap(),
                    String::from("derived"),
                    &Vec::new()
                ),
                &zero_vec
            )
        );
    }
}