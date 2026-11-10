use num_bigint::BigUint;
use num_traits::{pow, One, Zero};

/// Performs the x25519 key-generation algorithm on an input scalar and key. THIS VERSION
/// IS NOT SECURE. THERE IS A TIMING SIDE-CHANNEL WHICH CAN BE EXPLOITED.
pub fn x25519(mut k_bytes: [u8; 32], mut u_bytes: [u8; 32]) -> [u8; 32] {
    k_bytes[0] &= 248u8;
    k_bytes[31] &= 127u8;
    k_bytes[31] |= 64u8;

    u_bytes[31] &= 127u8;

    let k = BigUint::from_bytes_le(&k_bytes);
    let u = BigUint::from_bytes_le(&u_bytes);

    let x_1: BigUint = u.clone();
    let mut x_2: BigUint = BigUint::one();
    let mut z_2: BigUint = BigUint::zero();
    let mut x_3: BigUint = u.clone();
    let mut z_3: BigUint = BigUint::one();
    let a24: BigUint = BigUint::from(121665u128);
    let mut swap: BigUint = BigUint::zero();
    let two: BigUint = BigUint::from(2u32);

    let p: BigUint = pow(BigUint::from(2u32), 255usize) - BigUint::from(19u32);

    for t in (0..=254).rev() {
        let k_t: BigUint = (&k >> t) & BigUint::one();
        swap ^= &k_t;
        (x_2, x_3) = c_swap(&swap, x_2, x_3);
        (z_2, z_3) = c_swap(&swap, z_2, z_3);
        swap = k_t;

        let a: BigUint = (&x_2 + &z_2) % &p;
        let aa: BigUint = a.modpow(&two, &p);
        let b: BigUint = (&x_2 + &p - &z_2) % &p;
        let bb: BigUint = b.modpow(&two, &p);
        let e: BigUint = (&aa + &p - &bb) % &p;
        let c: BigUint = (&x_3 + &z_3) % &p;
        let d:BigUint = (x_3 + &p - z_3) % &p;
        let da: BigUint = (&d * &a) % &p;
        let cb: BigUint = (&c * &b) % &p;
        x_3 = (pow(&da + &cb, 2)) % &p;
        z_3 = (&x_1 * pow(da + &p - cb, 2)) % &p;
        x_2 = (&aa * &bb) % &p;
        z_2 = (&e * (&aa + &a24 * &e)) % &p
    }

    (x_2, _) = c_swap(&swap, x_2, x_3);
    (z_2, _) = c_swap(&swap, z_2, z_3);

    let mut result: Vec<u8> = BigUint::to_bytes_le(
        &((&x_2 * (
            z_2.modpow(&(&p - &two), &p)
        )) % &p));
    result.resize(32, 0u8);
    result.try_into().unwrap()
}

/// Should swap the parameters if swap is true.
fn c_swap(swap: &BigUint, num_2: BigUint, num_3: BigUint) -> (BigUint, BigUint) {
    if *swap == BigUint::one() {
        return(num_3, num_2);
    }

    (num_2, num_3)
}

#[derive(Default)]
pub struct Keys {
    pub private_key: Option<Vec<u8>>,
    pub public_key: Option<Vec<u8>>,
    pub shared_secret: Option<Vec<u8>>
}

impl Keys {
    pub fn new() -> Keys {
        let mut result: Keys = Keys::default();

        let mut scalar_bytes: Vec<u8> = BigUint::to_bytes_le(&BigUint::from(9u32));
        scalar_bytes.resize(32, 0u8);

        result.private_key = Some(Vec::from(rand::random::<[u8; 32]>()));
        result.public_key = Some(Vec::from(x25519(
            result.private_key.clone().unwrap().try_into().unwrap(),
            scalar_bytes.try_into().unwrap()
        )));

        result
    }

    pub fn calculate_shared_secret(&mut self, client_public_key: Vec<u8>) -> Vec<u8> {
        self.shared_secret = Some(Vec::from(x25519(
            self.private_key.clone().unwrap().try_into().unwrap(),
            client_public_key.try_into().unwrap()
        )));

        self.shared_secret.clone().unwrap()
    }
}
