use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
use libpaillier::{
    unknown_order::BigNumber,
    Ciphertext,
    DecryptionKey,
    EncryptionKey,
    // Randomness, // No longer needed
};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use secp256k1::Error::InvalidPublicKey;
use secp256k1::Error;

// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigNumber, // paillier encryption
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigNumber, // paillier encryption
}

impl MessageA {
  pub fn sample_below_bignumber(max: &BigNumber) -> BigNumber {
    let mut random_bytes = vec![0u8; max.bit_length()];
    getrandom::getrandom(&mut random_bytes).expect("Failed to generate random bytes");

    // Convert random bytes to a BigNumber less than max
    let mut result = BigNumber::from_bytes(&random_bytes);
    while result >= *max {
        result -= max;
    }

    result
}
    /// Creates a new `messageA` using Alice's Paillier encryption key.
    // Alice computes cA = EncryptA(a)
    pub fn a(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
    ) -> (Self, BigInt) {
        let randomness = MessageA::sample_below_bignumber(&alice_ek.n());
        let m_a = MessageA::a_with_predefined_randomness(a, alice_ek, &randomness);
        (m_a, randomness)
    }
    pub fn a_with_predefined_randomness(
      a: &Scalar<Secp256k1>,
      alice_ek: &EncryptionKey,
      randomness: &BigNumber,
  ) -> Self {
      let c_a = alice_ek.encrypt(randomness, &a.to_bigint()).unwrap();
      Self {
          c: c_a.into_owned(),
      }
    }
}


impl MessageB {
  pub fn sample_below_bignumber(max: &BigNumber) -> BigNumber {
    let mut random_bytes = vec![0u8; max.bit_length()];
    getrandom::getrandom(&mut random_bytes).expect("Failed to generate random bytes");

    // Convert random bytes to a BigNumber less than max
    let mut result = BigNumber::from_bytes(&random_bytes);
    while result >= *max {
        result -= max;
    }

    result
}
    // Bob selects β′ <– Zn.
    // Bob computes cB = b * cA + EncryptA(β′) = EncryptA(ab+β′).
    // Bob sets additive share β = -β′ mod q.
    
    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
    ) -> Result<(Self, Scalar<Secp256k1>, BigNumber, BigNumber), Error> {
        let beta_tag = MessageB::sample_below_bignumber(&alice_ek.n());
        let randomness = MessageB::sample_below_bignumber(&alice_ek.n());
        let (m_b, beta) = MessageB::b_with_predefined_randomness(
            b,
            alice_ek,
            m_a,
            &randomness,
            &beta_tag,
        )?;

        Ok((m_b, beta, randomness, beta_tag))
    }
    pub fn b_with_predefined_randomness(
      b: &Scalar<Secp256k1>,
      alice_ek: &EncryptionKey,
      m_a: MessageA,
      randomness: &BigNumber,
      beta_tag: &BigNumber,
  ) -> Result<(Self, Scalar<Secp256k1>), Error> {
      let beta_tag_fe = Scalar::<Secp256k1>::from(beta_tag);
      let c_beta_tag = alice_ek.encrypt(randomness, &beta_tag).unwrap();

      let b_bn = b.to_bigint();
      let b_c_a = alice_ek.mul(&m_a.c, &b_bn);
      let c_b = alice_ek.add(&b_c_a, &c_beta_tag).unwrap(); // Using `unwrap` for simplicity
      let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;
      Ok((
          Self {
              c: c_b.into_owned(),
          },
          beta,
      ))
    }
    // Alice decrypts α' = dec(cB).
    // Alice sets α = α′ mod q.
    
    pub fn verify_proofs_get_alpha(
      &self,
      dk: &DecryptionKey,
      a: &Scalar<Secp256k1>,
  ) -> Result<(Scalar<Secp256k1>, BigNumber), Error> {
      let alice_share = dk.decrypt(&self.c); // Using `&self.c` directly
      let alpha = Scalar::<Secp256k1>::from(&alice_share); // No need for `into_owned`
      Ok((alpha, alice_share))
        
    }
}


pub(crate) fn generate_init() -> (EncryptionKey, DecryptionKey) {
  let sk = DecryptionKey::random().unwrap();
    let ek = EncryptionKey::from(&sk);
    (ek, sk)
}


// fn mta(alice_input: &Scalar<Secp256k1>, bob_input: &Scalar<Secp256k1>) -> Result<Scalar<Secp256k1>,Scalar<Secp256k1>>{
//   let (ek_alice, dk_alice) = generate_init();
//   let (m_a, _) = MessageA::a(&alice_input, &ek_alice);
//   let (m_b, beta, _, _) = MessageB::b(&bob_input, &ek_alice, m_a).unwrap();
//   let alpha = m_b
//     .verify_proofs_get_alpha(&dk_alice, &alice_input)
//     .map_err(|e| e.into());

//   (alpha, beta)
// }
// fn main() {
//   let alice_input = Scalar::<Secp256k1>::random();
//   let bob_input = Scalar::<Secp256k1>::random();
//   let (alpha, beta) = mta(alice_input, bob_input);
//   let left = alpha.0 + beta;
//   let right = alice_input * bob_input;
//   assert_eq!(left, right);
// }
fn main() {
  let alice_input = Scalar::<Secp256k1>::random();
  let (ek_alice, dk_alice) = generate_init();
  let bob_input = Scalar::<Secp256k1>::random();
  let (m_a, _) = MessageA::a(&alice_input, &ek_alice);
  let (m_b, beta, _, _) = MessageB::b(&bob_input, &ek_alice, m_a).unwrap();
  let alpha = m_b
      .verify_proofs_get_alpha(&dk_alice, &alice_input)
      .expect("wrong dlog or m_b");

  let left = alpha.0 + beta;
  let right = alice_input * bob_input;
  assert_eq!(left, right);
}