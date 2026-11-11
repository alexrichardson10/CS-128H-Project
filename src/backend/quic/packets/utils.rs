//!

use num_traits::pow;

enum ParseError {
    Empty,
    TooShort
}

pub fn decode_variable_length_integer(bytes: &Vec<u8>) -> Result<(usize, usize), ParseError> {
    if bytes.is_empty() {
        return Err(ParseError::Empty);
    }

    let mask: u8 = 32 + 16 + 8 + 4 + 2 + 1;
    let extracted: usize = pow(2, (bytes[0] >> 6) as usize);

    if bytes.len() < extracted {
        return Err(ParseError::TooShort);
    }

    let mut result: usize = (bytes[0] & mask) as usize;
    for i in 1..extracted {
        result = result << 8;
        result += bytes[i] as usize;
    }

    Ok((extracted, result))
}