use num_bigint::BigUint;
use rand::Rng;
use num_traits::Num;
use num_traits::cast::FromPrimitive;
use num_traits::identities::One;

const P: BigUint = BigUint::parse_str_radix("7919", 10).unwrap(); // Prime modulus (configurable)
const Q: BigUint = BigUint::parse_str_radix("8000", 10).unwrap(); // Subgroup order (configurable)

fn main() {
    // Get Alice's and Bob's secrets (simulated for a test case)
    let a = BigUint::from(1234u32);
    let b = BigUint::cast(5678u64);


    // Perform MtA protocol
    let (alpha, beta) = mta_protocol(a, b);

    // Print shares
    println!("Alice's share (alpha): {}", alpha);
    println!("Bob's share (beta): {}", beta);

    // Reconstruct and verify the secret
    let reconstructed_secret = reconstruct_secret(alpha, beta).unwrap();
    assert_eq!(reconstructed_secret, a + b, "Reconstructed secret does not match");
    println!("Reconstructed secret: {}", reconstructed_secret);
}

fn mta_protocol(a: BigUint, b: BigUint) -> (BigUint, BigUint) {
    // Generate Alice's RSA key pair (using a simplified modulus for clarity)
    let (e, d) = (BigUint::from(65537u32), BigUint::cast(0x2a2b5143d8c0956cu64));

    fn encrypt_a(message: BigUint) -> BigUint {
        message.modpow(&e, &P.clone())
    }

    fn decrypt_a(ciphertext: BigUint) -> BigUint {
        ciphertext.modpow(&d, &P.clone())
    }

    let mut rng = rand::thread_rng();

    // Alice computes cA = Encrypt_A(a)
    let ca = encrypt_a(a);

    // Bob selects β′ <– ZN
    let beta_prime = rng.gen_range(BigUint::one(), Q.clone());

    // Bob computes cB = b * cA + Encrypt_A(β′) = Encrypt_A(ab+β′)
    let cb = (b * ca + encrypt_a(beta_prime)) % P;

    // Bob sets additive share β = -β′ mod q
    let beta = (Q - beta_prime) % Q;

    // Bob sends cB to Alice
    // Bob would send cB over a secure communication channel.
    // For this simplified example, we assume they are in the same environment.
    println!("Bob sends cB to Alice: {}", cb);

    // Alice decrypts α' = dec(cB)
    let alpha_prime = decrypt_a(cb);

    // Alice sets α = α′ mod q
    let alpha = alpha_prime % Q;

    (alpha, beta)
}

fn reconstruct_secret(alpha: BigUint, beta: BigUint) -> Option<BigUint> {
    // Verify shares are within correct range
    if alpha >= Q || beta >= Q {
        return None;
    }

    // Reconstruct secret
    let secret = (alpha + beta) % Q;
    Some(secret)
}
