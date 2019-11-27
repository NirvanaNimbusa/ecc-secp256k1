use bech32::{FromBase32, ToBase32, u5, convert_bits};
use bitcoin_hashes::{hash160, Hash, sha256};
use crate::secp256k1::{PrivateKey, PublicKey};

#[allow(dead_code)]
pub fn program_to_witness(version: u8, program: &[u8]) -> String {
    assert!(version <= 16u8);
    assert!(2 <= program.len() && program.len() <= 40);
    //assert!(version > 0u8 && (program.len() >= 20 && program.len() <= 40));
    let data = [vec![u5::try_from_u8(version).unwrap()], program.to_base32()].concat();

    bech32::encode("bcrt", data).unwrap()
}



#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility::bytes_to_hex;

    #[test]
    pub fn test_bech32() {
        let encoded = bech32::encode("bech32", vec![0x00, 0x01, 0x02].to_base32()).unwrap();
        assert_eq!(encoded, "bech321qqqsyrhqy2a".to_string());

        let (hrp, data) = bech32::decode(&encoded).unwrap();
        assert_eq!(hrp, "bech32");
        assert_eq!(Vec::<u8>::from_base32(&data).unwrap(), vec![0x00, 0x01, 0x02]);
    }

    #[test]
    pub fn test_hash_160() {
        let input = vec![
            0x04, 0xa1, 0x49, 0xd7, 0x6c, 0x5d, 0xe2, 0x7a, 0x2d,
            0xdb, 0xfa, 0xa1, 0x24, 0x6c, 0x4a, 0xdc, 0xd2, 0xb6,
            0xf7, 0xaa, 0x29, 0x54, 0xc2, 0xe2, 0x53, 0x03, 0xf5,
            0x51, 0x54, 0xca, 0xad, 0x91, 0x52, 0xe4, 0xf7, 0xe4,
            0xb8, 0x5d, 0xf1, 0x69, 0xc1, 0x8a, 0x3c, 0x69, 0x7f,
            0xbb, 0x2d, 0xc4, 0xec, 0xef, 0x94, 0xac, 0x55, 0xfe,
            0x81, 0x64, 0xcc, 0xf9, 0x82, 0xa1, 0x38, 0x69, 0x1a,
            0x55, 0x19,
        ];

        let output = vec![
            0xda, 0x0b, 0x34, 0x52, 0xb0, 0x6f, 0xe3, 0x41,
            0x62, 0x6a, 0xd0, 0x94, 0x9c, 0x18, 0x3f, 0xbd,
            0xa5, 0x67, 0x68, 0x26,
        ];

        let hash = hash160::Hash::hash(&input[..]);
        assert_eq!(&hash[..], &output[..]);
    }

    #[test]
    pub fn test_v0_address() {
        let key_hash = sha256::Hash::hash(b"key0");
        let priv_key = PrivateKey::from_serialized(&key_hash[..]);
        let pubkey = priv_key.generate_pubkey();

        assert_eq!("026C5D5E73124F3C821C0985DF787E11B3D018A86ADD577FA8661613A0D49DDE59", 
            bytes_to_hex(&pubkey.compressed()));

        let program = hash160::Hash::hash(&pubkey.compressed());
        let version = 0u8;
        let address = program_to_witness(version, &program);

        assert_eq!("bcrt1q4x4lwgmsdlatsfmpzgewtnuz9865arkcj6wj4r".to_string(), address);
    }
}