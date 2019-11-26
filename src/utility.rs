use crate::hash::HashTrait;

#[allow(dead_code)]
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter().map(|b| format!("{:02X}", b)).collect();
    strs.join("")
}


// an tagged hash implementation used in Bip Schnorr
#[allow(dead_code)]
pub fn tagged_hash(tag: &[u8], msg: &[u8]) -> [u8; 32] {
    let tag_hash1 = tag.hash_digest().to_vec();
    //for now allocating two different ones
    let tag_hash2 = tag_hash1.clone();
    [tag_hash1, tag_hash2, msg.to_vec()].concat().hash_digest()
}

#[allow(dead_code)]
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

    #[test]
    fn test_tagged_hash() {
        //zero message
        let msg = [0u8];
        //testing tags
        let test_tags = vec!["TapLeaf", "TapRoot", "TapBranch", "Random-Chutiyapa"];
        let mut results = Vec::new();
        for tag in test_tags {
            results.push(bytes_to_hex(tagged_hash(tag.as_bytes(), &msg).as_ref()));
        }
        // Good Results
        let good_results = vec![
            "ED1382037800C9DD938DD8854F1A8863BCDEB6705069B4B56A66EC22519D5829",
            "A7AB373B73939BA58031EED842B334D97E03664C51047E855F299462A8255D2F",
            "92534B1960C7E6245AF7D5FDA2588DB04AA6D646ABC2B588DAB2B69E5645EB1D",
            "4DC5D3BBBDA44AF536A9E7E2B7C080F3C0DA6AEC2E9B9DA2918A8ED66B83F9E1",
        ];

        assert_eq!(good_results, results);
    }
}
