pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join("")
}

pub fn hex_to_bytes(hex_asm: &str) -> Vec<u8> {
    let mut hex_bytes = hex_asm
        .as_bytes()
        .iter()
        .filter_map(|b| match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        })
        .fuse();

    let mut bytes = Vec::new();
    while let (Some(h), Some(l)) = (hex_bytes.next(), hex_bytes.next()) {
        bytes.push(h << 4 | l)
    }
    bytes
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_to_hex_string() {
        let bytes = [0xFF as u8, 0 as u8, 0xAA as u8];
        let actual = bytes_to_hex(&bytes);
        assert_eq!("FF00AA", actual);
    }

    #[test]
    fn test_hex_to_bytes() {
        let hex = "FF00AA";
        let bytes = [0xFF as u8, 0 as u8, 0xAA as u8];
        assert_eq!(hex_to_bytes(hex), bytes);
    }
}
