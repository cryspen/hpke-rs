/// Convert a hex string to a byte vector.
pub fn hex_to_bytes(hex: &str) -> Vec<u8> {
    assert!(hex.len() % 2 == 0);
    let mut bytes = Vec::new();
    for i in 0..(hex.len() / 2) {
        bytes.push(u8::from_str_radix(&hex[2 * i..2 * i + 2], 16).unwrap());
    }
    bytes
}

/// Convert a hex string to a byte vector.
/// If the input is `None`, this returns an empty vector.
pub fn hex_to_bytes_option(hex: Option<String>) -> Vec<u8> {
    match hex {
        Some(s) => hex_to_bytes(&s),
        None => vec![],
    }
}

/// Convert a byte slice into byte slice option.
/// Returns `Nonce` if the byte slice is empty and `Some(v)` otherwise.
pub fn vec_to_option_slice(v: &[u8]) -> Option<&[u8]> {
    if v.is_empty() {
        None
    } else {
        Some(v)
    }
}
