use crate::backend::quic::packets::frames::Frame;
use crate::backend::quic::packets::Packet;
use crate::backend::quic::packets::utils::{extract_dc_id, ParseError};
use crate::backend::server::connection::Connection;

pub mod connection;

#[derive(Debug)]
pub enum PacketParseError {
    BadDcId
}

pub struct Server {
    connections: Vec<Connection>,
}

impl Server {
    pub fn new() -> Server {
        let connections: Vec<Connection> = Vec::new();

        Server {
            connections
        }
    }

    pub fn parse_packet(&mut self, packet: &Vec<u8>) -> Result<Packet, PacketParseError> {
        let dc_id: Result<Vec<u8>, ParseError> = extract_dc_id(&packet);
        if dc_id.is_err() {
            return Err(PacketParseError::BadDcId);
        }
        let dc_id: Vec<u8> = dc_id.unwrap();

        let corresponding_connection: Option<&mut Connection> = self.get_connection(dc_id);
        let connection: &mut Connection;

        if corresponding_connection.is_some() {
            connection = corresponding_connection.unwrap();
        } else {
            self.connections.push(Connection::new());
            connection = self.connections.last_mut().unwrap();
        }

        let frames: Result<Vec<Frame>, ParseError> = connection.parse_packet(&packet);
        // todo!() parse frames

        Ok(connection.packet_history[connection.packet_history.len() - 1].clone())
    }

    pub fn get_connection(&mut self, dc_id: Vec<u8>) -> Option<&mut Connection> {
        for connection in self.connections.iter_mut() {
            if connection.dc_ids.contains(&dc_id) {
                return Some(connection);
            }
        }

        None
    }
}