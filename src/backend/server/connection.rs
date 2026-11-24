use std::collections::HashSet;
use crate::backend::crypto::diffie_hellman::Keys;
use crate::backend::crypto::quic::QuicKeySchedule;
use crate::backend::crypto::tls::TlsKeySchedule;
use crate::backend::quic::packets::frames::Frame;
use crate::backend::quic::packets::initial::InitialPacket;
use crate::backend::quic::packets::Packet;
use crate::backend::quic::packets::Packet::Initial;
use crate::backend::quic::packets::utils::ParseError;

#[derive(Default)]
pub struct PacketNumbers {
    pub highest_received: Option<u64>,
    pub highest_sent: Option<u64>
}

#[derive(Default)]
/// A good deal of this is probably redundant, but I'm saving it anyway for diagnostics
pub struct Connection {
    pub keys: Keys,
    pub tls_key_schedule: TlsKeySchedule,
    pub quic_key_schedule: QuicKeySchedule,

    pub dc_ids: HashSet<Vec<u8>>,

    pub packet_numbers: PacketNumbers,

    pub transcript: Vec<u8>,
    
    // storing this is DEFINITELY not necessary, but I'm going to do it anyway.
    pub packet_history: Vec<Packet>,
}

impl Connection {
    pub fn new() -> Connection {
        Connection::default()
    }

    /// Parses a packet sent from a client, updates the connection's state accordingly.
    pub fn parse_packet(&mut self, packet: &Vec<u8>) -> Result<Vec<Frame>, ParseError> {
        if packet.is_empty() {
            return Err(ParseError::Empty);
        }

        // Long header branch
        if packet[0] & 128 == 128 {
            // Initial packet branch
            if packet[0] & 48 == 0 {
                let parsed_packet: InitialPacket = InitialPacket::from(self, packet);
                let frames: Vec<Frame> = parsed_packet.frames.clone();
                self.packet_history.push(Initial(parsed_packet));
                
                return Ok(frames);
            }
            
            todo!()
        }

        // Short header branch
        else {
            todo!()
        }
    }

    pub fn eval_frames(&mut self, frames: &Vec<Frame>) {

    }
}