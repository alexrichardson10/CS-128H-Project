use num_bigint::BigUint;
use crate::backend::diffie_hellman;

#[test]
/// Tests the x25519 implementation against the rfc7748 test key found at
/// https://www.rfc-editor.org/info/rfc7748/#section-6.1
pub fn diffie_hellman_x25519() {
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
}