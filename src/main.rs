#![allow(unused_imports)]
use num_bigint::BigUint;
use rand::Rng;
use num_traits::Num;
use num_traits::cast::FromPrimitive;
use num_traits::identities::One;

use num_traits::ToPrimitive;
use rand::distributions::{Distribution, Uniform};
use lazy_static::lazy_static;
use std::ops::Rem;
use num_traits::CheckedSub;


//const P: BigUint = BigUint::parse_bytes(b"7919", 10).unwrap(); // Prime modulus (configurable)
//const Q: BigUint = BigUint::parse_bytes(b"8000", 10).unwrap(); // Subgroup order (configurable)

lazy_static! {
    static ref P: BigUint = BigUint::parse_bytes(b"7919", 10).unwrap(); // Prime modulus (configurable)
    static ref Q: BigUint = BigUint::parse_bytes(b"8000", 10).unwrap(); // Subgroup order (configurable)
}

fn main() {
    // Get Alice's and Bob's secrets (simulated for a test case)
    let a = BigUint::from(1234u32);
    let b = BigUint::from_u64(5678u64).unwrap();
    //let b = BigUint::cast(5678u64);

     // Print shares
     println!("(preMTA)- Alice's share (a): {:?}", &a);
     println!("(preMTA)- Bob's share (b): {:?}", &b);


    // Perform MtA protocol
    let (alpha, beta) = mta_protocol(&a, &b);
    dbg!(&alpha+&beta);

    // Print shares
    println!("Alice's share (alpha): {:?}", alpha);
    println!("Bob's share (beta): {:?}", beta);

    // Reconstruct and verify the secret
    let reconstructed_secret = reconstruct_secret(alpha, beta).unwrap();
    dbg!((&a*&b)%Q.clone() );
    
    assert_eq!(reconstructed_secret, a * b % Q.clone() , "Reconstructed secret does not match");
    println!("Reconstructed secret: {}", reconstructed_secret);
}

fn mta_protocol(a: & BigUint, b: & BigUint) -> (BigUint, BigUint) {
    // Generate Alice's RSA key pair (using a simplified modulus for clarity)
    //let (e, d) = (BigUint::from(65537u32), BigUint::cast(0x2a2b5143d8c0956cu64));
    let (e, d) = (BigUint::from(65537u32), BigUint::from_u64(0x2a2b5143d8c0956cu64).unwrap());

    fn encrypt_a(
        e: &BigUint,
        message: &BigUint
    ) -> BigUint {
        message.modpow(&e, &P.clone())
    }

    fn decrypt_a(
        d: &BigUint,
        ciphertext: BigUint
    ) -> BigUint {
        ciphertext.modpow(&d, &P.clone())
    }

    let mut rng = rand::thread_rng();

    // Alice computes cA = Encrypt_A(a)
    let ca = encrypt_a(&e, &a);

    // Bob selects β′ <– ZN
    //let beta_prime = rng.gen_range(BigUint::one(), Q.clone());

    let q_u64 = Q.to_u64().expect("Q value too large for u64");
    let one = BigUint::one();

    let range = Uniform::new_inclusive(one.to_u64().unwrap(), q_u64);
    let beta_prime_u64 = range.sample(&mut rng);

    let beta_prime = BigUint::from_u64(beta_prime_u64).unwrap();
    // Bob computes cB = b * cA + Encrypt_A(β′) = Encrypt_A(ab+β′)
    //let cb = (b * ca + encrypt_a(&e, beta_prime)) % P;

    let cb = (b * ca + encrypt_a(&e, &beta_prime)) % P.clone();


    // Bob sets additive share β = -β′ mod q
    //let beta = (*Q - beta_prime) % *Q;
    let beta = Q.clone() - (beta_prime % Q.clone());
    //let beta = (Q.checked_sub(&beta_prime).unwrap_or_else(|| Q.clone() - &beta_prime)) % Q.clone();


    // Bob sends cB to Alice
    // Bob would send cB over a secure communication channel.
    // For this simplified example, we assume they are in the same environment.
    println!("Bob sends cB to Alice: {}", cb);

    // Alice decrypts α' = dec(cB)
    let alpha_prime = decrypt_a(&d, cb);

    // Alice sets α = α′ mod q
    let alpha = alpha_prime % Q.clone();

    (alpha, beta)
}

fn reconstruct_secret(alpha: BigUint, beta: BigUint) -> Option<BigUint> {
    // Verify shares are within correct range
    if alpha >= *Q || beta >= *Q {
        return None;
    }

    //dbg!(&alpha);
    //dbg!(&beta);

    // Reconstruct secret
    Some((alpha * beta)% Q.clone())

}
