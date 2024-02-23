use curv::arithmetic::traits::Samplable;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
// use paillier::arithimpl::gmpimpl::BigInt;
use paillier::traits::EncryptWithChosenRandomness;
use paillier::{Add, Decrypt, Mul};
use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
use paillier::KeyGeneration;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use secp256k1::Error::InvalidPublicKey;
use secp256k1::Error;

// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigInt, // paillier encryption
}

// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigInt, // paillier encryption
}

impl MessageA {
    /// Creates a new `messageA` using Alice's Paillier encryption key.
    // Alice computes cA = EncryptA(a)
    pub fn a(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
    ) -> (Self, BigInt) {
        let randomness = BigInt::sample_below(&alice_ek.n);
        let m_a = MessageA::a_with_predefined_randomness(a, alice_ek, &randomness);
        (m_a, randomness)
    }
    pub fn a_with_predefined_randomness(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        randomness: &BigInt,
    ) -> Self {
        let c_a = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(a.to_bigint()),
            &Randomness::from(randomness.clone()),
        )
        .0
        .clone()
        .into_owned();
        Self {
            c: c_a,
        }
    }
}

impl MessageB {
    // Bob selects β′ <– Zn.
    // Bob computes cB = b * cA + EncryptA(β′) = EncryptA(ab+β′).
    // Bob sets additive share β = -β′ mod q.

    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
    ) -> Result<(Self, Scalar<Secp256k1>, BigInt, BigInt), Error> {
        let beta_tag = BigInt::sample_below(&alice_ek.n);
        let randomness = BigInt::sample_below(&alice_ek.n);
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
        randomness: &BigInt,
        beta_tag: &BigInt,
    ) -> Result<(Self, Scalar<Secp256k1>), Error> {
        let beta_tag_fe = Scalar::<Secp256k1>::from(beta_tag);
        let c_beta_tag = Paillier::encrypt_with_chosen_randomness(
            alice_ek,
            RawPlaintext::from(beta_tag),
            &Randomness::from(randomness.clone()),
        );

        let b_bn = b.to_bigint();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(m_a.c),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a, c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;
        Ok((
            Self {
                c: c_b.0.clone().into_owned(),
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
    ) -> Result<(Scalar<Secp256k1>, BigInt), Error> {
        let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        let alpha = Scalar::<Secp256k1>::from(alice_share.0.as_ref());
        
            Ok((alpha, alice_share.0.into_owned()))
        
    }
}

pub(crate) fn generate_init() -> (EncryptionKey, DecryptionKey) {
    let (ek, dk) = Paillier::keypair().keys();
    (ek, dk)
}


fn mta(alice_input: &Scalar<Secp256k1>, bob_input: &Scalar<Secp256k1>) -> Result<(Scalar<Secp256k1>),(Scalar<Secp256k1>)>{
  let (ek_alice, dk_alice) = generate_init();
  let (m_a, _) = MessageA::a(&alice_input, &ek_alice);
  let (m_b, beta, _, _) = MessageB::b(&bob_input, &ek_alice, m_a).unwrap();
  let alpha = m_b
    .verify_proofs_get_alpha(&dk_alice, &alice_input)
    .map_err(|e| e.into());

  alpha, beta
}
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