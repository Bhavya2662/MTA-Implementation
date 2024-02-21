use rand::Rng;
use num_bigint::BigUint;

const P: BigUint = BigUint::from_str_radix("7919", 10).unwrap(); // Prime modulus (configurable)
const Q: BigUint = BigUint::from_str_radix("8000", 10).unwrap(); // Subgroup order (configurable)



fn main() {
    // Get Alice's and Bob's secrets
    let a = get_positive_integer("Alice's secret: ");
    let b = get_positive_integer("Bob's secret: ");

    // Perform MtA protocol
    let (alpha, beta) = mta_protocol(a, b);

    // Print shares
    println!("Alice's share (alpha): {}", alpha);
    println!("Bob's share (beta): {}", beta);

    // Verify secret reconstruction (optional)
    if let Some(reconstructed_secret) = reconstruct_secret(alpha, beta) {
        println!("Reconstructed secret: {}", reconstructed_secret);
        assert_eq!(reconstructed_secret, a + b); // Assert correct reconstruction
    } else {
        println!("Invalid shares (secret reconstruction failed)");
    }
}

fn get_positive_integer(prompt: &str) -> BigUint {
    loop {
        let mut input = String::new();
        println!("{}", prompt);
        std::io::stdin().read_line(&mut input).unwrap();
        let num = input.trim().parse::<BigUint>().unwrap_or_else(|_| {
            println!("Invalid input. Please enter a positive integer.");
            std::process::exit(1);
        });
        if num > BigUint::zero() {
            return num;
        }
        println!("Please enter a positive integer.");
    }
}

fn mta_protocol(a: BigUint, b: BigUint) -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();

    // Alice
    let ca = encrypt_a(a);
    println!("Alice sends cA to Bob: {}", ca);

    // Bob
    let beta_prime = rng.gen_bigint_range(BigUint::one(), Q.clone());
    let cb = (b * ca + encrypt_a(beta_prime)) % P;
    let beta = (Q - beta_prime) % Q;
    println!("Bob sends cB to Alice: {}", cb);

    // Alice
    let alpha_prime = decrypt_a(cb);
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
fn generate_rsa_keypair(p: BigUint) -> (BigUint, BigUint) {
    let mut rng = rand::thread_rng();

    // Choose two large prime numbers, p and q
    let q = rng.gen_bigint_range(BigUint::one(), p.clone());

    // Calculate n = p * q
    let n = p * q;

    // Calculate phi(n) = (p - 1) * (q - 1)
    let phi = (p - BigUint::one()) * (q - BigUint::one());

    // Choose an integer e such that 1 < e < phi(n) and gcd(e, phi(n)) = 1
    let e = rng.gen_bigint_range(BigUint::one(), phi.clone())
        .filter(|e| e.gcd(&phi) == BigUint::one())
        .next()
        .unwrap();

    // Calculate d such that 1 < d < phi(n) and e * d ≡ 1 (mod phi(n))
    let d = mod_inverse(e, phi).unwrap();

    (e, d)
}

// Generate RSA key pair (public key: (e, P), private key: (d, P))
let (e, d) = generate_rsa_keypair(P.clone());

fn encrypt_a(message: BigUint) -> BigUint {
    // Encrypt using the public key (e, P)
    message.modpow(&e, P.clone())
}

fn decrypt_a(ciphertext: BigUint) -> BigUint {
    // Decrypt using the private key (d, P)
    ciphertext.modpow(&d, P.clone())
}