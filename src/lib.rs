mod field;
mod point;
mod secp256k1;
mod hash;

pub use secp256k1::{Signature, PublicKey, PrivateKey};

#[cfg(test)]
mod tests {
    use super::*;
    use self::secp256k1::*;
    use rug::Integer;

    #[test]
    fn it_works() {
        let s1: Integer = Integer::u_pow_u(2,32).into();
        let s2: Integer = Integer::u_pow_u(2,31).into();
        let s = s1 + s2;

        let privkey = PrivateKey::new(s);
        let pubkey = privkey.generate_pubkey();
        println!("{}", pubkey);
        println!("{:?}", &pubkey.clone().uncompressed()[..]);
        println!("{:?}", &pubkey.compressed()[..]);

    }
}