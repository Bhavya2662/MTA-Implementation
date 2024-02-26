use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
// use curv::BigInt;
// use paillier::traits::EncryptWithChosenRandomness;
// use paillier::{Add, Decrypt, Mul};
// use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
// use paillier::KeyGeneration;
use libpaillier::{
  unknown_order::BigNumber,
  *
};
use rand::{Rng, thread_rng};

use serde::{Deserialize, Serialize};
use sha2::Sha256;

fn sample_below(modulus: &BigNumber) -> BigNumber {
  let mut rng = thread_rng();
  let mut random_num = BigNumber::from(0);

  // Loop until a number less than the modulus is generated
  while random_num >= *modulus {
      random_num = BigNumber::from(rng.gen_range(0, modulus.to_u64().unwrap_or(0)));
  }

  random_num
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigNumber,                     // paillier encryption
  }

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigNumber, // paillier encryption
}

impl MessageA {
    // pub fn a(
    //     a: &Scalar<Secp256k1>,
    //     alice_ek: &EncryptionKey,
    // ) -> (Self, BigNumber) {
    //     let randomness = sample_below(&alice_ek.n);
    //     let m_a = MessageA::a_with_predefined_randomness(a, alice_ek, &randomness );
    //     (m_a, randomness)
    // }

    pub fn a(
        a: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
    ) -> Self {
      
        let c_a = alice_ek.encrypt(a, None);
        // let c_a = EncryptionKey::encrypt(
        //     alice_ek,
        //     RawPlaintext::from(a.to_bigint()),
        //     &Randomness::from(randomness.clone()),
        // )
        // .0
        // .clone()
        // .into_owned();

        Self {
            c: c_a,
        }
    }
}

impl MessageB {
    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
    ) -> Result<(Self, Scalar<Secp256k1>, BigInt, BigInt)> {
        // let beta_tag = BigInt::sample_below(&alice_ek.n);
        let randomness = BigInt::sample_below(&alice_ek.n);
        let (m_b, beta) = MessageB::b_with_predefined_randomness(
            b,
            alice_ek,
            m_a,
            &randomness,
        )?;

        Ok((m_b, beta, randomness))
    }

    pub fn b_with_predefined_randomness(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
        randomness: &BigInt,
    ) -> Result<(Self, Scalar<Secp256k1>)> {
       
        let b_bn = b.to_bigint();
        let b_c_a = Paillier::mul(
            alice_ek,
            RawCiphertext::from(m_a.c),
            RawPlaintext::from(b_bn),
        );
        let c_b = Paillier::add(alice_ek, b_c_a);
        let beta = Scalar::<Secp256k1>::zero() ;


        Ok((
            Self {
                c: c_b.0.clone().into_owned(),
                
            },
            beta,
        ))
    }

    pub fn get_alpha(
        &self,
        dk: &DecryptionKey,
        a: &Scalar<Secp256k1>,
    ) -> Result<(Scalar<Secp256k1>, BigNumber)> {
        let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        // let g = Point::generator();
        
        let alpha = Scalar::<Secp256k1>::from(alice_share.0.as_ref());
        // let g_alpha = g * &alpha;
        
            Ok((alpha, alice_share.0.into_owned()))
       
    }

}
pub(crate) fn generate_init() -> (EncryptionKey, DecryptionKey) {
  
  let dk = DecryptionKey::random();
  let sk = res.unwrap();
  let ek = EncryptionKey::from(&sk);

  (ek, dk)
}
fn main() {
  let alice_input = Scalar::<Secp256k1>::random();
  let (ek_alice, dk_alice) = generate_init();
  let bob_input = Scalar::<Secp256k1>::random();
  let (m_a, _) = MessageA::a(&alice_input, &ek_alice);
  let (m_b, beta, _) = MessageB::b(&bob_input, &ek_alice, m_a).unwrap();
  let alpha = m_b
      .get_alpha(&dk_alice, &alice_input)
      .expect("wrong dlog or m_b");

  let left = alpha.0 + beta;
  let right = alice_input * bob_input;
  assert_eq!(left, right);
}
