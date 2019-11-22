use crate::secp256k1::{PrivateKey, PublicKey};
use rug::Integer;

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

pub fn sum_over_pubkeys(pubkeys: Vec<&PublicKey>) -> PublicKey {
    pubkeys.iter().fold(PublicKey::zero_pubkey(), |agg, x| agg + *x)
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
    }#[test]
    fn test_sum_over_pubkeys() {
         //make private keys
        let key_1 = PrivateKey::new(Integer::from(101));
        let key_2 = PrivateKey::new(Integer::from(222));
        let key_3 = PrivateKey::new(Integer::from(333));

        let R1 = key_1.generate_pubkey();
        let R2 = key_2.generate_pubkey();
        let R3 = key_3.generate_pubkey();

        let ans = sum_over_pubkeys(vec!(&R1, &R2, &R3));

        assert_eq!("02f90c3416d74049bf27b5563067c58401ff466e4bb04e1fa4d51ae4c93b4a8316".to_uppercase(),
                    bytes_to_hex(&ans.compressed()))
    }


}
