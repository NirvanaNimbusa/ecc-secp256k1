use crate::hash::{HashTrait};
use crate::secp256k1::{PrivateKey, PublicKey, Scalar};
use crate::utility::bytes_to_hex;
use std::convert::TryInto;

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
}
