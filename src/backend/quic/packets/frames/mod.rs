use crate::backend::quic::packets::frames::crypto::Crypto;
use crate::backend::quic::packets::frames::padding::Padding;

pub mod crypto;
pub mod padding;
pub mod ack;

#[derive(Debug)]
pub enum ParseError {
    ProtocolViolation
}

#[derive(Debug, Clone)]
pub enum Frame {
    Crypto(Crypto),
    Padding(Padding),
    Unimplemented
}

impl Frame {
    pub fn parse(data: &Vec<u8>) -> Result<Vec<Frame>, ParseError> {
        if data.len() == 0 {
            return Err(ParseError::ProtocolViolation)
        }

        let mut result: Vec<Frame> = Vec::new();
        let mut position: usize = 0;

        while position < data.len() {
            result.push(
                match data[position] {
                    0x00 => Frame::Padding(Padding::new(data, &mut position)),
                    0x06 => Frame::Crypto(Crypto::new(data, &mut position)),

                    _ => Frame::Unimplemented
                }
            );
        }

        Ok(result)
    }
}