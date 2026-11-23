pub enum HeaderType {
    Long,
    Short
}

pub enum QuicHeaderError {
    EmptyHeader,
    TooShortHeader,
    BadFixedBit,
    WrongPacketType,
    TooLargeDestinationConnectionIdLength,
    TooLargeSourceConnectionIdLength
}

impl HeaderType {
    pub fn type_of(header: &Vec<u8>) -> Result<HeaderType, QuicHeaderError> {
        if header.len() == 0 {
            return Err(QuicHeaderError::EmptyHeader);
        }

        // extracts the first bit from the first byte of the packet
        if header[0] >> 7 == 1 {
            return Ok(HeaderType::Long);
        }

        Ok(HeaderType::Short)
    }
}

#[derive(PartialEq)]
pub enum LongHeaderPacketType {
    VersionNegotiation,
    Initial,
    ZeroRTT,
    Handshake,
    Retry
}

pub struct ProtectedEncryptedLongHeader {
    header_form: u8,
    fixed_bit: u8,
    long_packet_type: LongHeaderPacketType,
    protected_bits: u8,
    remaining_bytes: Vec<u8>
}

pub struct EncryptedLongHeader {
    header_form: u8,
    fixed_bit: u8,
    long_packet_type: LongHeaderPacketType,
    reserved_bits: u8,
    packet_number_length: u8,
    
}

pub struct LongHeader {
    header_form: u8, // 1 = long, 0 = short
    fixed_bit: u8, // MUST be 1 unless a packet is a version negotiation packet
    long_packet_type: LongHeaderPacketType,
    protected_bits: u8,
    reserved_bits: Option<u8>,
    packet_number_length: Option<u8>,
    version: [u8; 4],
    destination_connection_id_length: u8, // MUST NOT exceed 20
    destination_connection_id: Vec<u8>,
    source_connection_id_length: u8, // MUST NOT exceed 20
    source_connection_id: Vec<u8>,
    type_specific_payload: Vec<u8>
}

impl LongHeader {
    pub fn new(header: &Vec<u8>) -> Result<LongHeader, QuicHeaderError> {
        if header.is_empty() {
            return Err(QuicHeaderError::EmptyHeader);
        }

        let header_form: u8 = header[0] >> 7;
        if header_form == 0 {
            return Err(QuicHeaderError::WrongPacketType);
        }

        let fixed_bit: u8 = (header[0] >> 6) % 2;

        let mut long_packet_type: LongHeaderPacketType = match (header[0] >> 4) % 4 {
            0 => LongHeaderPacketType::Initial,
            1 => LongHeaderPacketType::ZeroRTT,
            2 => LongHeaderPacketType::Handshake,
            3 => LongHeaderPacketType::Retry,
            _ => panic!("Math is broken") // this should NEVER happen but rust got angry
        };

        let protected_bits: u8 = header[0] % 16;

        /* let (reserved_bits, packet_number_length): (Option<u8>, Option<u8>) =
            if long_packet_type != LongHeaderPacketType::Retry {
                (Some(header[0] >> 2 % 4), Some(header[0] % 4))
            } else {
                (None, None)
            }; */

        // 6 is the length of the first byte + 4 version bytes + 1 dest_conn_id_len byte
        if header.len() < 6 {
            return Err(QuicHeaderError::TooShortHeader);
        }

        let mut version: [u8; 4] = [0; 4];
        for j in 0..4 { version[j] = header[j + 1]; }

        // probably a better way to do this.
        // I don't really care.
        if version[0] == 0 && version[1] == 0 && version[2] == 0 && version[3] == 0 {
            long_packet_type = LongHeaderPacketType::VersionNegotiation;

            if fixed_bit != 0 {
                return Err(QuicHeaderError::BadFixedBit);
            }
        } else {
            if fixed_bit == 0 {
                return Err(QuicHeaderError::BadFixedBit);
            }
        }

        let destination_connection_id_length: u8 = header[5];

        if destination_connection_id_length > 20 {
            return Err(QuicHeaderError::TooLargeDestinationConnectionIdLength);
        }

        let mut i: usize = 6;

        if header.len() < i + destination_connection_id_length as usize + 1 {
            return Err(QuicHeaderError::TooShortHeader);
        }

        let destination_connection_id: Vec<u8> =
            header[i..(i + destination_connection_id_length as usize)].to_vec();

        i += destination_connection_id_length as usize;

        let source_connection_id_length: u8 = header[i];

        if source_connection_id_length > 20 {
            return Err(QuicHeaderError::TooLargeSourceConnectionIdLength);
        }

        i += 1;

        if header.len() < i + source_connection_id_length as usize {
            return Err(QuicHeaderError::TooShortHeader);
        }

        let source_connection_id: Vec<u8> =
            header[i..(i + source_connection_id_length as usize)].to_vec();

        i += source_connection_id_length as usize;

        let type_specific_payload: Vec<u8> = header[i..].to_vec();

        Ok(LongHeader {
            header_form,
            fixed_bit,
            long_packet_type,
            protected_bits,
            reserved_bits: None,
            packet_number_length: None,
            version,
            destination_connection_id_length,
            destination_connection_id,
            source_connection_id_length,
            source_connection_id,
            type_specific_payload
        })
    }

    pub fn remove_header_protection(&mut self) {
        todo!()
    }
}

/* todo!() add short header struct
pub struct ShortHeader {

} */