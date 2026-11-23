//!

use num_traits::pow;

#[derive(Debug)]
pub enum ParseError {
    Empty,
    TooShort
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

/// THIS IS UNSAFE.
/// THE PACKET NUMBER REPRESENTATION TRANSMITTED IS NOT GUARANTEED TO BE COMPLETE.
/// TODO!() FIX THIS!!!!!!!
pub fn reconstruct_packet_number(truncated_packet_number: &Vec<u8>) -> Vec<u8> {
    truncated_packet_number.clone()
}