#![cfg(test)]

extern crate secp256k1 as test_secp256k1;

use crate::hash::HashTrait;
use crate::{PrivateKey, PublicKey, Signature};
use rand::{thread_rng, Rng};
use test_secp256k1::{
    rand::thread_rng as TestRng, Message as TestMessage, PublicKey as TestPublicKey,
    Secp256k1 as TestSecp256k1, SecretKey as TestPrivateKey, Signature as TestSignature,
};

#[test]
fn test_cmp_sign_der() {
    let mut rng = thread_rng();

    let key: [u8; 32] = rng.gen();
    let priv_key = PrivateKey::from_serialized(&key);
    let msg = get_rand_msg();

    let orig_sig = priv_key.sign(&msg).serialize_der();
    let pubkey = priv_key.generate_pubkey().compressed();

    // Verify with rust-secp256k1

    let secp = TestSecp256k1::verification_only();
    let pubkey = TestPublicKey::from_slice(&pubkey).unwrap();
    let msg = TestMessage::from_slice(&msg.hash_digest()).unwrap();
    println!("{:?}", msg);
    let sig = TestSignature::from_der(&orig_sig).unwrap();
    assert_eq!(sig.serialize_der(), orig_sig);
    assert!(secp.verify(&msg, &sig, &pubkey).is_ok())
}

#[test]
fn test_cmp_sign_compact() {
    let mut rng = thread_rng();

    let key: [u8; 32] = rng.gen();
    let priv_key = PrivateKey::from_serialized(&key);
    let msg = get_rand_msg();

    let orig_sig = priv_key.sign(&msg).serialize();
    let pubkey = priv_key.generate_pubkey().compressed();

    // Verify with rust-secp256k1

    let secp = TestSecp256k1::verification_only();
    let pubkey = TestPublicKey::from_slice(&pubkey).unwrap();
    let msg = TestMessage::from_slice(&msg.hash_digest()).unwrap();
    println!("{:?}", msg);
    let sig = TestSignature::from_compact(&orig_sig).unwrap();
    assert_eq!(&sig.serialize_compact()[..], &orig_sig[..]);
    assert!(secp.verify(&msg, &sig, &pubkey).is_ok())
}

fn get_rand_msg() -> Vec<u8> {
    let mut rng = thread_rng();
    let msg_len: usize = rng.gen_range(1, 1024);
    let mut msg = vec![0u8; msg_len];
    rng.fill(&mut msg[..]);
    msg
}

#[test]
fn test_verify_compact_uncompressed() {
    // Sign with rust-secp256k1
    let secp = TestSecp256k1::new();
    let orig_msg = get_rand_msg();
    let msg = TestMessage::from_slice(&orig_msg.hash_digest()).unwrap();
    let privkey = TestPrivateKey::new(&mut TestRng());
    let sig = secp.sign(&msg, &privkey).serialize_compact();
    let pubkey = TestPublicKey::from_secret_key(&secp, &privkey).serialize_uncompressed();

    // Verify with This library

    let sig = Signature::parse(sig);
    let pubkey = PublicKey::from_uncompressed(&pubkey);
    assert!(pubkey.verify(&orig_msg, sig));
}

#[test]
fn test_verify_der_compressed() {
    // Sign with rust-secp256k1
    let secp = TestSecp256k1::new();
    let orig_msg = get_rand_msg();
    let msg = TestMessage::from_slice(&orig_msg.hash_digest()).unwrap();
    let privkey = TestPrivateKey::new(&mut TestRng());
    let sig = secp.sign(&msg, &privkey).serialize_der();
    let pubkey = TestPublicKey::from_secret_key(&secp, &privkey).serialize();

    // Verify with This library

    let sig = Signature::parse_der(&sig);
    let pubkey = PublicKey::from_compressed(&pubkey);
    assert!(pubkey.verify(&orig_msg, sig));
}