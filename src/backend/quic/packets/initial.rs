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
use crate::backend::quic::packets::utils::{decode_variable_length_integer, reconstruct_packet_number};

/// The token and length are both stored as variable length integers, so
/// their actual lengths aren't necessarily 8 bytes.
#[derive(Debug)]
pub struct InitialPacket {
    first_byte: u8, // should be 110000XX once protection is removed
    version: [u8; 4],
    dc_id_len: u8,
    dc_id: Vec<u8>, // this is actually material for key generation
    sc_id_len: u8,
    sc_id: Vec<u8>,
    token_len: u64, // this should probably be 0x00
    token: Vec<u8>, // this should probably be empty
    length: u64,
    packet_number: Vec<u8>, // between 1 and 4 bytes, length is equal to the bottom
                            // two bits of the first byte + 1
    pub encrypted_packet_payload: Vec<u8>, // at least 1 byte
    pub authentication_tag: [u8; 16],

    pub associated_data: Vec<u8>,
    pub reconstructed_packet_number: Vec<u8>,
    pub packet_payload: Vec<u8>,
}

impl InitialPacket {
    // todo!() bounds checking, this panics if too short
    pub fn from(packet: Vec<u8>) -> InitialPacket {
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
        let client_initial_keys: KeySet = key_schedule.client_initial_keys.unwrap();
        let mask: [u8; 5] = aes_128_ecb::encrypt(
            client_initial_keys.hp.try_into().unwrap(),
            sample)[0..5].try_into().unwrap();

        let first_byte: u8 = packet[0] ^ (mask[0] & 0x0f);

        let packet_number_length: u8 = (first_byte & 0x03) + 1;
        let mut packet_number: Vec<u8> =
            packet[location..(location + packet_number_length as usize)].try_into().unwrap();
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

        InitialPacket {
            first_byte,
            version,
            dc_id_len,
            dc_id,
            sc_id_len,
            sc_id,
            token_len,
            token,
            length,
            packet_number,
            encrypted_packet_payload,
            authentication_tag,
            associated_data,
            reconstructed_packet_number,
            packet_payload,
        }
    }
}