/*
Initial Packet {
  Header Form (1) = 1,
  Fixed Bit (1) = 1,
  Long Packet Type (2) = 0,
  Reserved Bits (2),         # Protected
  Packet Number Length (2),  # Protected
  Version (32),
  DCID Len (8),
  Destination Connection ID (0..160),
  SCID Len (8),
  Source Connection ID (0..160),
  Token Length (i),
  Token (..),
  Length (i),
  Packet Number (8..32),     # Protected
  Protected Payload (0..24), # Skipped Part
  Protected Payload (128),   # Sampled Part
  Protected Payload (..)     # Remainder
}
 */
use crate::backend::crypto::{aead_aes_128_gcm, aes_128_ecb};
use crate::backend::crypto::quic::{KeySet, QuicKeySchedule};
use crate::backend::quic::packets::frames::Frame;
use crate::backend::quic::packets::utils::{decode_variable_length_integer, encode_variable_length_integer, encode_variable_length_integer_from_vec, reconstruct_packet_number};
use crate::backend::server::connection::Connection;
use crate::backend::utils::to_u64;

/// The token and length are both stored as variable length integers, so
/// their actual lengths aren't necessarily 8 bytes.
#[derive(Debug, Clone)]
pub struct InitialPacket {
    protected_first_byte: u8,
    first_byte: u8, // should be 110000XX once protection is removed

    version: [u8; 4],
    dc_id_len: u8,
    dc_id: Vec<u8>, // this is actually material for key generation
    sc_id_len: u8,
    sc_id: Vec<u8>,

    token_len_bytes_read: u64,
    token_len: u64, // this should probably be 0x00
    token: Vec<u8>, // this should probably be empty

    length_bytes_read: u64,
    length: u64,

    protected_packet_number: Vec<u8>,
    packet_number: Vec<u8>, // between 1 and 4 bytes, length is equal to the bottom
                            // two bits of the first byte + 1
    pub reconstructed_packet_number: Vec<u8>,

    pub encrypted_packet_payload: Vec<u8>, // at least 1 byte
    pub packet_payload: Vec<u8>,

    pub authentication_tag: [u8; 16],
    pub associated_data: Vec<u8>,

    pub frames: Vec<Frame>,
}

impl InitialPacket {
    // todo!() bounds checking, this panics if too short
    pub fn from(connection: &mut Connection, packet: &Vec<u8>) -> InitialPacket {
        let mut location: usize = 0;

        // in order to read the full packet contents the header protection
        // needs to be removed first. we need to sample the first four bytes
        // after the start of the packet number field for this.

        location += 1; // this bypasses the first byte, which is currently protected

        let version: [u8; 4] = packet[location..(location + 4)].try_into().unwrap();
        location += 4;

        let dc_id_len: u8 = packet[location];
        location += 1;
        let dc_id: Vec<u8> = packet[location..(location + dc_id_len as usize)].to_vec();
        location += dc_id_len as usize;

        let sc_id_len: u8 = packet[location];
        location += 1;
        let sc_id: Vec<u8> = packet[location..(location + sc_id_len as usize)].to_vec();
        location += sc_id_len as usize;

        // I'm fairly certain this should always be zero but will load it anyway
        let (token_len_bytes_read, token_len) =
            decode_variable_length_integer(&packet[location..].to_vec()).unwrap();
        location += token_len_bytes_read as usize;
        let token: Vec<u8> = packet[location..(location + token_len as usize)].to_vec();
        location += token_len as usize;

        let (length_bytes_read, length) =
            decode_variable_length_integer(&packet[location..].to_vec()).unwrap();
        location += length_bytes_read as usize;
        let end: usize = location + length as usize;

        // location's start is now the beginning of the packet_number field
        let sample: [u8; 16] = packet[(location + 4)..(location + 20)].try_into().unwrap();

        // fun crypto stuff :(
        let key_schedule: QuicKeySchedule = QuicKeySchedule::from(&dc_id);
        let client_initial_keys: KeySet = key_schedule.client_initial_keys.clone().unwrap();
        let mask: [u8; 5] = aes_128_ecb::encrypt(
            client_initial_keys.hp.try_into().unwrap(),
            sample)[0..5].try_into().unwrap();

        let first_byte: u8 = packet[0] ^ (mask[0] & 0x0f);

        let packet_number_length: u8 = (first_byte & 0x03) + 1;
        let protected_packet_number: Vec<u8> =
            packet[location..(location + packet_number_length as usize)].try_into().unwrap();
        let mut packet_number: Vec<u8> = protected_packet_number.clone();
        for i in 0..packet_number.len() {
            packet_number[i] ^= mask[i + 1];
        }
        location += packet_number_length as usize;

        let mut associated_data: Vec<u8> =
            packet[0..(location - packet_number_length as usize)].to_vec();
        associated_data.extend(&packet_number);
        associated_data[0] = first_byte;

        /* let mut associated_data: Vec<u8> = packet[0..location].to_vec();
        associated_data[0] = first_byte;
        for i in 0..packet_number_length {
            associated_data[length as usize - packet_number_length as usize + i as usize] =
                packet_number[i as usize];
        } */

        //let packet_payload: Vec<u8> = Vec::new();
        let encrypted_packet_payload: Vec<u8> = packet[location..(end - 16)].to_vec();
        let authentication_tag: [u8; 16] = packet[(end - 16)..end].try_into().unwrap();

        // this function doesn't work yet
        let reconstructed_packet_number: Vec<u8> = reconstruct_packet_number(&packet_number);

        let packet_payload: Vec<u8> = aead_aes_128_gcm::decrypt(
            &client_initial_keys.key,
            &client_initial_keys.iv,
            &reconstructed_packet_number,
            &associated_data,
            &encrypted_packet_payload,
            &(authentication_tag.try_into().unwrap())
        ).unwrap();

        let frames: Vec<Frame> = Frame::parse(&packet_payload).unwrap();

        let protected_first_byte = packet[0];

        // Updates the connection's state
        connection.quic_key_schedule = key_schedule;
        connection.dc_ids.insert(dc_id.clone());
        connection.packet_numbers.highest_received = Some(to_u64(&packet_number).unwrap());

        InitialPacket {
            protected_first_byte,
            first_byte,
            version,
            dc_id_len,
            dc_id,
            sc_id_len,
            sc_id,
            token_len_bytes_read,
            token_len,
            token,
            length_bytes_read,
            length,
            protected_packet_number,
            packet_number,
            encrypted_packet_payload,
            authentication_tag,
            associated_data,
            reconstructed_packet_number,
            packet_payload,
            frames,
        }
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result: Vec<u8> = Vec::new();

        result.push(self.protected_first_byte);
        result.extend(self.version);
        result.push(self.dc_id_len);
        result.extend(self.dc_id.clone());
        result.push(self.sc_id_len);
        result.extend(self.sc_id.clone());
        result.extend(encode_variable_length_integer (
            self.token_len_bytes_read as usize,
            self.token_len.clone()
        ).unwrap());
         result.extend(self.token.clone());
        result.extend(encode_variable_length_integer (
             self.length_bytes_read as usize,
             self.length
         ).unwrap());
        result.extend(self.protected_packet_number.clone());
        result.extend(self.encrypted_packet_payload.clone());
        result.extend(self.authentication_tag.clone());

        result
    }

    /*/// Makes a response to the other initial packet provided. A lot of things
    /// are hard-coded here that really shouldn't be. I'm forcing a particular
    /// encryption algorithm (I was too lazy to implement more) and doing a lot
    /// of horrible things here that should really get this thrown away. Too Bad!
    pub fn make_response_to(other: &InitialPacket) -> InitialPacket {
        let first_byte = 128 + 64;

        let version: [u8; 4] = other.version.clone();

        let dc_id_len: u8 = other.dc_id_len;
        let dc_id: Vec<u8> = other.dc_id.clone();

        let sc_id_len: u8 = other.sc_id_len;
        let sc_id: Vec<u8> = other.sc_id.clone();

        // this is one of the areas the packets differ
        // I obviously don't have a token to show the client, that's *THEIR* job.
        let token_len_bytes_read: u64 = 1;
        let token_len: u64 = 0;
        let token: Vec<u8> = Vec::new();

        // these are the same because I'm not bothering to shorten them.
        let packet_number: Vec<u8> = Vec::from([0u8]);
        let reconstructed_packet_number: Vec<u8> = Vec::from([0u8]);

        InitialPacket {
            protected_first_byte: u8,
            first_byte,

            version,
            dc_id_len,
            dc_id,
            sc_id_len,
            sc_id,

            token_len_bytes_read,
            token_len,
            token,

            length_bytes_read: u64,
            length: u64,

            protected_packet_number: Vec<u8>,
            packet_number,
            reconstructed_packet_number,

            encrypted_packet_payload: Vec<u8>, // at least 1 byte
            packet_payload: Vec<u8>,

            authentication_tag: [u8; 16],
            associated_data: Vec<u8>,

            frames: Vec<Frame>,
        }
    }*/
}