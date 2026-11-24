use crate::backend::quic::packets::initial::InitialPacket;

pub mod initial;
pub mod utils;

#[cfg(test)]
mod tests;
pub mod frames;

#[derive(Clone, Debug)]
pub enum Packet {
    Initial(InitialPacket)
}