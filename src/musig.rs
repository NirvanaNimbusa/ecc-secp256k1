use crate::hash::{HashTrait};
use crate::secp256k1::{PrivateKey, PublicKey, Scalar};
use crate::utility::{
    bytes_to_hex,
    sum_over_pubkeys,
    };
use std::convert::TryInto;
use rug::Integer;

pub fn get_agg_musig_pubkey(pubkeys: &[PublicKey]) -> (Vec<(Scalar, PublicKey)>, PublicKey) {

    //Collect the x-coordinate of pubkeys into a vector
    let mut collection: Vec<[u8; 32]> = Vec::new();
    for pubkey in pubkeys {
        collection.push(pubkey.clone().compressed()[1..].try_into().unwrap());
    }

    //sort the vector 
    collection.sort();

    // unbag the vector into a Vec<u8>
    // preperation for hashing
    let col_array: Vec<u8> = collection.iter().fold(Vec::new(), |agg, x| [agg, x.clone().to_vec()].concat());

    // hash it
    let c_all = col_array.hash_digest();

    // Construct the challenge tupple
    let mut challenge = Vec::new();
    for pubkey in pubkeys {
        let c_i = [c_all, pubkey.clone().compressed()[1..].try_into().unwrap()].concat().hash_digest();
        challenge.push((Scalar::new(&c_i), pubkey.clone()));
    }

    // Crunch out aggreagate pubkey = sum (pubkey_i * c_i)
    let agg_pubkey = challenge.iter().fold(PublicKey::zero_pubkey(), |agg, x| agg + (&x.1 * &x.0));

    // Return (Challenge tupple, Aggregate Pubkey)
    (challenge, agg_pubkey)
}

pub fn agg_schnorr_nonces(nonce_points: Vec<&PublicKey>) -> (PublicKey, bool) {
    let sum = sum_over_pubkeys(nonce_points);
    if !sum.is_square_y() {
        (sum.negate(), true)
    } else {
        (sum, false)
    } 
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_agg_musig_pubkey() {
        //make Private Key from hash digest
        let privkey_1 = PrivateKey::from_serialized(&b"key0".hash_digest()[..]);
        let privkey_2 = PrivateKey::from_serialized(&b"key1".hash_digest()[..]);
        let privkey_3 = PrivateKey::from_serialized(&b"key2".hash_digest()[..]);

        //make corresponding pubkeys
        let pubkey_1 = privkey_1.generate_pubkey();
        let pubkey_2 = privkey_2.generate_pubkey();
        let pubkey_3 = privkey_3.generate_pubkey();

        let (challenges, agg_pubkey) = get_agg_musig_pubkey(&[pubkey_1, pubkey_2, pubkey_3]);

        assert_eq!(
            "02eeeea7d79f3ecde08d2a3c59f40eb3adcac9defb77d3b92053e5df95165139cd".to_uppercase(),
            bytes_to_hex(&agg_pubkey.compressed())
        );
    }

    #[test]
    fn test_agg_schnorr_nonces() {
        //make private keys
        let key_1 = PrivateKey::new(Integer::from(101));
        let key_2 = PrivateKey::new(Integer::from(222));
        let key_3 = PrivateKey::new(Integer::from(333));

        let R1 = key_1.generate_pubkey();
        let R2 = key_2.generate_pubkey();
        let R3 = key_3.generate_pubkey();
        /*
        let R1_digest = R1.compressed().hash_digest();
        let R2_digest = R2.compressed().hash_digest();
        let R3_digest = R3.compressed().hash_digest();

        assert_eq!("aa5d4a40c1843456534d75f7246b9cbf0f825a36113102e76193f80e6c652c72".to_uppercase(), 
                   bytes_to_hex(&R1_digest));

        assert_eq!("6a78f2c6ca3bf1364f0575a02ef334d176df2051084c0e3062ec2af79b5b406a".to_uppercase(),
                    bytes_to_hex(&R2_digest));

        assert_eq!("bc2c379a7b6ad82b40a7cf280697505ccc039370e50eb155324dcac3b5faa6a5".to_uppercase(),
                    bytes_to_hex(&R3_digest));
        
        */
        let correct_r_agg = "03f90c3416d74049bf27b5563067c58401ff466e4bb04e1fa4d51ae4c93b4a8316".to_uppercase();

        let (calculated_r_agg, negated) = agg_schnorr_nonces(vec!(&R1, &R2, &R3));

        assert_eq!(correct_r_agg, bytes_to_hex(&calculated_r_agg.compressed()));


    }
}
