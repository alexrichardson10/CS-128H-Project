use crate::backend::quic::header::{LongHeader, QuicHeaderError};

pub mod crypto;
pub mod quic;

pub fn run() {
    let mut packet: Vec<u8> = Vec::new();
    packet.push(128u8);
    let h: Result<LongHeader, QuicHeaderError> = LongHeader::new(&packet);
}