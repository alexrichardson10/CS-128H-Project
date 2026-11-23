use crate::backend::crypto::diffie_hellman::Keys;
use crate::backend::crypto::quic::QuicKeySchedule;
use crate::backend::crypto::tls::TlsKeySchedule;

pub struct PacketNumbers {
    highest_received: u64,
    highest_sent: u64
}

pub struct Connection {
    keys: Keys,
    tls_key_schedule: TlsKeySchedule,
    quic_key_schedule: QuicKeySchedule,
    packet_numbers: PacketNumbers,
}

impl Connection {
    pub fn new() {

    }
}