/// Creates a byte array from the length, label, label prefix, and context
/// for use in hkdf-expand
pub fn make_label(length: u16, label: String, context: &Vec<u8>) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    let length_bytes: Vec<u8> = Vec::from(u16::to_be_bytes(length));
    let prefix_bytes: Vec<u8> = Vec::from("tls13 ".as_bytes());
    let label_bytes: Vec<u8> = Vec::from(label.as_bytes());

    for byte in length_bytes.iter() {
        result.push(*byte);
    }

    result.push(prefix_bytes.len() as u8 + label_bytes.len() as u8);

    for byte in prefix_bytes.iter() {
        result.push(*byte);
    }

    for byte in label_bytes.iter() {
        result.push(*byte);
    }

    result.push(context.len() as u8);

    for byte in context.iter() {
        result.push(*byte);
    }

    result
}

pub fn hkdf_expand_label(
    secret: &Vec<u8>,
    label: String,
    context: &Vec<u8>,
    length: u16
) -> Vec<u8> {
    hkdf_expand(
        secret,
        &make_label(length, label, context),
        length
    )
}

pub fn hkdf_extract(
    salt: &Vec<u8>,
    ikm: &Vec<u8>,
) -> Vec<u8> {
    let prk = hmac_sha256::HKDF::extract(salt, ikm);

    prk.to_vec()
}


pub fn hkdf_expand(
    prk: &[u8],
    info: &Vec<u8>,
    l: u16,
) -> Vec<u8> {
    let mut okm: Vec<u8> = Vec::new();
    okm.resize(l as usize, 0);
    hmac_sha256::HKDF::expand(&mut okm, prk, info);

    okm
}

pub fn derive_secret(
    secret: &Vec<u8>,
    label: String,
    messages: &Vec<u8>
) -> Vec<u8> {
    let hashed_messages: Vec<u8> = Vec::from(hmac_sha256::Hash::hash(messages));
    hkdf_expand_label(
        secret,
        label,
        &hashed_messages,
        hashed_messages.len() as u16
    )
}