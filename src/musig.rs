use crate::hash::HashTrait;
use crate::secp256k1::{get_context, PrivateKey, PublicKey, Scalar, SchnorrSignature};
use rug::{integer::Order, Integer};
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

pub fn agg_schnorr_nonces(nonce_points: &[PublicKey]) -> (PublicKey, bool) {
    let sum: PublicKey = nonce_points.iter().sum();
    if !sum.is_square_y() {
        (sum.negate(), true)
    } else {
        (sum, false)
    }
}

pub fn sign_musig(privkey: &PrivateKey, nonce: &PrivateKey, R_agg: &PublicKey, Pub_agg: &PublicKey, msg: &[u8; 32]) -> [u8; 32] {
    let secp = get_context();
    assert!(Integer::from_digits(&privkey.serialize(), Order::MsfBe) < secp.order);
    assert_ne!(Integer::from_digits(&privkey.serialize(), Order::MsfBe), 0);
    assert!(R_agg.is_square_y());

    let data = [R_agg.compressed()[1..].to_vec(), Pub_agg.compressed()[..].to_vec(), msg[..].to_vec()].concat();

    let e = Scalar::new(&data.hash_digest());

    let s = nonce + &(privkey * &e);

    s.serialize()
}

pub fn aggregate_musig_signatures(sigs: &[[u8; 32]], R_agg: &PublicKey) -> SchnorrSignature {
    let integers: Vec<Integer> = sigs.iter().map(|sig| Integer::from_digits(sig, Order::MsfBe)).collect();
    let sum: Integer = integers.iter().fold(Integer::new(), |agg, x| (agg + x) % &get_context().order);
    let mut s = [0u8; 32];
    s[..].copy_from_slice(&sum.to_digits(Order::MsfBe));
    let mut r = [0u8; 32];
    r[..].copy_from_slice(&R_agg.compressed()[1..]);

    SchnorrSignature::new(&r, &s)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utility::bytes_to_hex;

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

        // Tweak Priv key as per challenges
        let privkey_1_c = privkey_1 * &challenges[0].0;
        let privkey_2_c = privkey_2 * &challenges[1].0;
        let privkey_3_c = privkey_3 * &challenges[2].0;

        // assert aggregate pubkeys as tweaks
        assert_eq!(
            "02eeeea7d79f3ecde08d2a3c59f40eb3adcac9defb77d3b92053e5df95165139cd".to_uppercase(),
            bytes_to_hex(&agg_pubkey.compressed())
        );

        assert_eq!("E7840B6872AF61DCA5EDB4B1334958D1FAB3D1851F376D0C4252881404AEC711", bytes_to_hex(&privkey_1_c.serialize()));

        assert_eq!("90EEBF5AFFD698DFB4B938B5FAB1943287F867AB31B07D18FCA33FF7D984BADC", bytes_to_hex(&privkey_2_c.serialize()));

        assert_eq!("EC8F1CDE74C3151170CAEB9C2A25FF69F2EF25EF89AD07C195FA1F44DDB6C290", bytes_to_hex(&privkey_3_c.serialize()));

        //make nonce keys
        let mut key_1 = PrivateKey::new(Integer::from(101));
        let mut key_2 = PrivateKey::new(Integer::from(222));
        let mut key_3 = PrivateKey::new(Integer::from(333));

        // Generate Nonce Points
        let R1 = key_1.generate_pubkey();
        let R2 = key_2.generate_pubkey();
        let R3 = key_3.generate_pubkey();

        /*
        let R1_digest = R1.clone().compressed().hash_digest();
        let R2_digest = R2.clone().compressed().hash_digest();
        let R3_digest = R3.clone().compressed().hash_digest();

        assert_eq!("aa5d4a40c1843456534d75f7246b9cbf0f825a36113102e76193f80e6c652c72".to_uppercase(),
                   bytes_to_hex(&R1_digest));

        assert_eq!("6a78f2c6ca3bf1364f0575a02ef334d176df2051084c0e3062ec2af79b5b406a".to_uppercase(),
                    bytes_to_hex(&R2_digest));

        assert_eq!("bc2c379a7b6ad82b40a7cf280697505ccc039370e50eb155324dcac3b5faa6a5".to_uppercase(),
                    bytes_to_hex(&R3_digest));
        */
        let (calculated_r_agg, negated) = agg_schnorr_nonces(&[R1, R2, R3]);

        if negated {
            key_1 = key_1.negate();
            key_2 = key_2.negate();
            key_3 = key_3.negate();
        }

        let correct_r_agg = "03f90c3416d74049bf27b5563067c58401ff466e4bb04e1fa4d51ae4c93b4a8316".to_uppercase();

        assert_eq!(correct_r_agg, bytes_to_hex(&calculated_r_agg.compressed()));

        // Partial Signatures
        let msg = b"transaction".hash_digest();
        let s1 = sign_musig(&privkey_1_c, &key_1, &calculated_r_agg, &agg_pubkey, &msg);
        let s2 = sign_musig(&privkey_2_c, &key_2, &calculated_r_agg, &agg_pubkey, &msg);
        let s3 = sign_musig(&privkey_3_c, &key_3, &calculated_r_agg, &agg_pubkey, &msg);

        assert_eq!("911A969C1BD3A3E9881026D51CD3936017EABB53CA35966E1A942E55A3F9EF1F", bytes_to_hex(&s1));

        assert_eq!("6C7D713005AA61E2BBF7A1E19AA0D53E1A33DD9EF0C8449F18FE4FF2BAF6D057", bytes_to_hex(&s2));

        assert_eq!("588CFD807EEC08AE32E50180E1E0CE6DDF8A4543B60BAB51A01D2F16B7F7B65F", bytes_to_hex(&s3));

        // signature aggregation
        let sig_agg = aggregate_musig_signatures(&[s1, s2, s3], &calculated_r_agg);

        assert_eq!("F90C3416D74049BF27B5563067C58401FF466E4BB04E1FA4D51AE4C93B4A83165625054CA06A0E7A76ECCA379955370D56FA014FC1C0E62313DD4ED246B23494",
                    bytes_to_hex(&sig_agg.serialize()));
    }
}
