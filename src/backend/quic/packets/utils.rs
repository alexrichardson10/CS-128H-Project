//!

use num_traits::pow;

#[derive(Debug)]
pub enum ParseError {
    Empty,
    TooShort,
    InvalidLength
}

pub fn decode_variable_length_integer(bytes: &Vec<u8>) -> Result<(u64, u64), ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }

    let mask: u8 = 32 + 16 + 8 + 4 + 2 + 1;
    let extracted: u64 = pow(2, (bytes[0] >> 6) as usize);

    if bytes.len() < extracted as usize {
        return Err(ParseError::TooShort);
    }

    let mut result: u64 = (bytes[0] & mask) as u64;
    for i in 1..extracted {
        result = result << 8;
        result += bytes[i as usize] as u64;
    }

    Ok((extracted, result))
}

pub fn encode_variable_length_integer_from_vec(mut value: Vec<u8>) -> Result<Vec<u8>, ParseError> {
    if value.len() == 0 {
        return Ok(Vec::new());
    }

    value[0] |= match value.len() {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return Err(ParseError::InvalidLength)
    } << 6;

    Ok(value)
}

pub fn encode_variable_length_integer(length: usize, value: u64) -> Result<Vec<u8>, ParseError> {
    let mut value_vec = value.to_be_bytes().to_vec();
    value_vec = value_vec[(8 - length)..].to_vec();

    if length == 0 && value == 0 {
        return Ok(Vec::new());
    }

    value_vec[0] |= match length {
        1 => 0,
        2 => 1,
        4 => 2,
        8 => 3,
        _ => return Err(ParseError::InvalidLength)
    } << 6;

    Ok(value_vec)
}

/// THIS IS UNSAFE.
/// THE PACKET NUMBER REPRESENTATION TRANSMITTED IS NOT GUARANTEED TO BE COMPLETE.
/// TODO!() FIX THIS!!!!!!!
pub fn reconstruct_packet_number(truncated_packet_number: &Vec<u8>) -> Vec<u8> {
    truncated_packet_number.clone()
}

pub fn extract_dc_id(packet: &Vec<u8>) -> Result<Vec<u8>, ParseError> {
    if packet.len() == 0 {
        return Err(ParseError::Empty);
    }

    // long headers
    if packet[0] & 128 == 128 {
        if packet.len() < 6 {
            return Err(ParseError::TooShort);
        }

        let dc_id_len: u8 = packet[5];

        if packet.len() < 6 + dc_id_len as usize {
            return Err(ParseError::TooShort);
        }

        Ok(packet[6..(6 + dc_id_len as usize)].to_vec())
    }

    // short headers
    else {
        // I'm always going to issue a dc-id of 8 bytes, so extracting this is easy
        if packet.len() < 9 {
            return Err(ParseError::TooShort);
        }

        Ok(packet[1..9].to_vec())
    }
}