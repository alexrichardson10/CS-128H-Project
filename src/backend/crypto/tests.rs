use crate::backend::crypto::diffie_hellman;
use crate::backend::crypto::hkdf::{hkdf_expand, hkdf_extract};
use num_bigint::BigUint;

#[test]
/// Tests the x25519 implementation against the RFC 7748 test keys found at
/// https://www.rfc-editor.org/info/rfc7748/
pub fn diffie_hellman_x25519() {
    // Alice & Bob key exchange per RFC 7748 §6.1
    // Alice's private key, in little endian hex.
    let alice_private_str: &str = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a";
    let mut alice_private_bytes: Vec<u8> = hex::decode(alice_private_str).unwrap();
    alice_private_bytes.resize(32, 0);
    let alice_private: [u8; 32] = alice_private_bytes.try_into().unwrap();

    // Bob's private key, in little endian hex.
    let bob_private_str: &str = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb";
    let mut bob_private_bytes: Vec<u8> = hex::decode(bob_private_str).unwrap();
    bob_private_bytes.resize(32, 0);
    let bob_private: [u8; 32] = bob_private_bytes.try_into().unwrap();

    // Alice's expected public key, in little endian hex.
    let alice_public_str: &str = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a";
    let mut alice_public_bytes: Vec<u8> = hex::decode(alice_public_str).unwrap();
    alice_public_bytes.resize(32, 0);
    let alice_public: [u8; 32] = alice_public_bytes.try_into().unwrap();

    // Bob's expected public key, in little endian hex.
    let bob_public_str: &str = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    let mut bob_public_bytes: Vec<u8> = hex::decode(bob_public_str).unwrap();
    bob_public_bytes.resize(32, 0);
    let bob_public: [u8; 32] = bob_public_bytes.try_into().unwrap();

    // Their expected shared secret, in little endian hex.
    let shared_str: &str = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742";
    let mut shared_bytes: Vec<u8> = hex::decode(shared_str).unwrap();
    shared_bytes.resize(32, 0);
    let shared: [u8; 32] = shared_bytes.try_into().unwrap();

    // The scalar used for computing public keys.
    let mut scalar_bytes: Vec<u8> = BigUint::to_bytes_le(&BigUint::from(9u32));
    scalar_bytes.resize(32, 0u8);
    let scalar: [u8; 32] = scalar_bytes.try_into().unwrap();

    let solved_alice_public: [u8; 32] = diffie_hellman::x25519(alice_private, scalar);
    let solved_bob_public: [u8; 32] = diffie_hellman::x25519(bob_private, scalar);
    let solved_shared_alice: [u8; 32] = diffie_hellman::x25519(alice_private, solved_bob_public);
    let solved_shared_bob: [u8; 32] = diffie_hellman::x25519(bob_private, solved_alice_public);

    assert_eq!(alice_public, solved_alice_public);
    assert_eq!(bob_public, solved_bob_public);
    assert_eq!(shared, solved_shared_alice);
    assert_eq!(shared, solved_shared_bob);

    // Test Vector 1 per RFC 7748 §5.2
    let scalar_1_str: &str = "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4";
    let mut scalar_1_bytes: Vec<u8> = hex::decode(scalar_1_str).unwrap();
    scalar_1_bytes.resize(32, 0);
    let scalar_1: [u8; 32] = scalar_1_bytes.try_into().unwrap();

    let u_1_str: &str = "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c";
    let mut u_1_bytes: Vec<u8> = hex::decode(u_1_str).unwrap();
    u_1_bytes.resize(32, 0);
    let u_1: [u8; 32] = u_1_bytes.try_into().unwrap();

    let shared_1_str: &str = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552";
    let mut shared_1_bytes: Vec<u8> = hex::decode(shared_1_str).unwrap();
    shared_1_bytes.resize(32, 0);
    let shared_1: [u8; 32] = shared_1_bytes.try_into().unwrap();

    let solved_1: [u8; 32] = diffie_hellman::x25519(scalar_1, u_1);

    assert_eq!(shared_1, solved_1);

    // Test Vector 2 per RFC 7748 §5.2
    let scalar_2_str: &str = "4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d";
    let mut scalar_2_bytes: Vec<u8> = hex::decode(scalar_2_str).unwrap();
    scalar_2_bytes.resize(32, 0);
    let scalar_2: [u8; 32] = scalar_2_bytes.try_into().unwrap();

    let u_2_str: &str = "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493";
    let mut u_2_bytes: Vec<u8> = hex::decode(u_2_str).unwrap();
    u_2_bytes.resize(32, 0);
    let u_2: [u8; 32] = u_2_bytes.try_into().unwrap();

    let shared_2_str: &str = "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957";
    let mut shared_2_bytes: Vec<u8> = hex::decode(shared_2_str).unwrap();
    shared_2_bytes.resize(32, 0);
    let shared_2: [u8; 32] = shared_2_bytes.try_into().unwrap();

    let solved_2: [u8; 32] = diffie_hellman::x25519(scalar_2, u_2);

    assert_eq!(shared_2, solved_2);

    // Test Vector type 2 per RFC 7748 §5.2
    // Omitted for time considerations, can be uncommented for a more comprehensive test.
    // let scalar_type_2_str: &str = "0900000000000000000000000000000000000000000000000000000000000000";
    // let mut scalar_type_2_bytes: Vec<u8> = hex::decode(scalar_type_2_str).unwrap();
    // scalar_type_2_bytes.resize(32, 0);
    // let mut scalar_type_2: [u8; 32] = scalar_type_2_bytes.try_into().unwrap();
    //
    // let u_type_2_str: &str = "0900000000000000000000000000000000000000000000000000000000000000";
    // let mut u_type_2_bytes: Vec<u8> = hex::decode(u_type_2_str).unwrap();
    // u_type_2_bytes.resize(32, 0);
    // let mut u_type_2: [u8; 32] = u_type_2_bytes.try_into().unwrap();
    //
    // let shared_type_2_str: &str = "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51";
    // let mut shared_type_2_bytes: Vec<u8> = hex::decode(shared_type_2_str).unwrap();
    // shared_type_2_bytes.resize(32, 0);
    // let shared_type_2: [u8; 32] = shared_type_2_bytes.try_into().unwrap();
    //
    // for _ in 1..=999 {
    // let temp: [u8; 32] = diffie_hellman::x25519(scalar_type_2, u_type_2);
    //
    // u_type_2 = scalar_type_2;
    // scalar_type_2 = temp;
    // }
    //
    // let solved_type_2: [u8; 32] = diffie_hellman::x25519(scalar_type_2, u_type_2);
    //
    // assert_eq!(shared_type_2, solved_type_2);
}

#[test]
/// Tests the hkdf implementation against the test vectors found at
/// https://www.rfc-editor.org/info/rfc5869/
pub fn hkdf() {
    // Test Vector 1 per RFC 5869 §A.1
    let ikm_1_str: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let mut ikm_1: Vec<u8> = hex::decode(ikm_1_str).unwrap();
    ikm_1.resize(22, 0);

    let salt_1_str: &str = "000102030405060708090a0b0c";
    let mut salt_1: Vec<u8> = hex::decode(salt_1_str).unwrap();
    salt_1.resize(13, 0);

    let info_1_str: &str = "f0f1f2f3f4f5f6f7f8f9";
    let mut info_1: Vec<u8> = hex::decode(info_1_str).unwrap();
    info_1.resize(10, 0);

    let l_1: u16 = 42;

    let prk_1_str: &str = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
    let mut prk_1: Vec<u8> = hex::decode(prk_1_str).unwrap();
    prk_1.resize(32, 0);

    let okm_1_str: &str = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";
    let mut okm_1: Vec<u8> = hex::decode(okm_1_str).unwrap();
    okm_1.resize(42, 0);

    let solved_prk_1 = hkdf_extract(&salt_1, &ikm_1);
    let solved_okm_1 = hkdf_expand(&prk_1, &info_1, l_1);

    assert_eq!(prk_1, solved_prk_1);
    assert_eq!(okm_1, solved_okm_1);

    // Test Vector 2 per RFC 5869 §A.2
    let ikm_2_str: &str = concat!(
          "000102030405060708090a0b0c0d0e0f",
          "101112131415161718191a1b1c1d1e1f",
          "202122232425262728292a2b2c2d2e2f",
          "303132333435363738393a3b3c3d3e3f",
          "404142434445464748494a4b4c4d4e4f");
    let mut ikm_2: Vec<u8> = hex::decode(ikm_2_str).unwrap();
    ikm_2.resize(80, 0);

    let salt_2_str: &str = concat!(
          "606162636465666768696a6b6c6d6e6f",
          "707172737475767778797a7b7c7d7e7f",
          "808182838485868788898a8b8c8d8e8f",
          "909192939495969798999a9b9c9d9e9f",
          "a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    let mut salt_2: Vec<u8> = hex::decode(salt_2_str).unwrap();
    salt_2.resize(80, 0);

    let info_2_str: &str = concat!(
          "b0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
          "c0c1c2c3c4c5c6c7c8c9cacbcccdcecf",
          "d0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
          "e0e1e2e3e4e5e6e7e8e9eaebecedeeef",
          "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
    let mut info_2: Vec<u8> = hex::decode(info_2_str).unwrap();
    info_2.resize(80, 0);

    let l_2: u16 = 82;

    let prk_2_str: &str = concat!(
          "06a6b88c5853361a06104c9ceb35b45c",
          "ef760014904671014a193f40c15fc244");
    let mut prk_2: Vec<u8> = hex::decode(prk_2_str).unwrap();
    prk_2.resize(32, 0);

    let okm_2_str: &str = concat!(
          "b11e398dc80327a1c8e7f78c596a4934",
          "4f012eda2d4efad8a050cc4c19afa97c",
          "59045a99cac7827271cb41c65e590e09",
          "da3275600c2f09b8367793a9aca3db71",
          "cc30c58179ec3e87c14c01d5c1f3434f",
          "1d87");
    let mut okm_2: Vec<u8> = hex::decode(okm_2_str).unwrap();
    okm_2.resize(82, 0);

    let solved_prk_2 = hkdf_extract(&salt_2, &ikm_2);
    let solved_okm_2 = hkdf_expand(&prk_2, &info_2, l_2);

    assert_eq!(prk_2, solved_prk_2);
    assert_eq!(okm_2, solved_okm_2);

    // Test Vector 3 per RFC 5869 §A.3
    let ikm_3_str: &str = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
    let mut ikm_3: Vec<u8> = hex::decode(ikm_3_str).unwrap();
    ikm_3.resize(22, 0);

    let salt_3_str: &str = "";
    let mut salt_3: Vec<u8> = hex::decode(salt_3_str).unwrap();
    salt_3.resize(0, 0);

    let info_3_str: &str = "";
    let mut info_3: Vec<u8> = hex::decode(info_3_str).unwrap();
    info_3.resize(0, 0);

    let l_3: u16 = 42;

    let prk_3_str: &str = concat!(
          "19ef24a32c717b167f33a91d6f648bdf",
          "96596776afdb6377ac434c1c293ccb04");
    let mut prk_3: Vec<u8> = hex::decode(prk_3_str).unwrap();
    prk_3.resize(32, 0);

    let okm_3_str: &str = concat!(
          "8da4e775a563c18f715f802a063c5a31",
          "b8a11f5c5ee1879ec3454e5f3c738d2d",
          "9d201395faa4b61a96c8");
    let mut okm_3: Vec<u8> = hex::decode(okm_3_str).unwrap();
    okm_3.resize(42, 0);

    let solved_prk_3 = hkdf_extract(&salt_3, &ikm_3);
    let solved_okm_3 = hkdf_expand(&prk_3, &info_3, l_3);

    assert_eq!(prk_3, solved_prk_3);
    assert_eq!(okm_3, solved_okm_3);
}