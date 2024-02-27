use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use curv::BigInt;
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
use generic_array::{GenericArray, typenum::U32};

fn to_bytes(obj: &Scalar<Secp256k1>) -> Vec<u8> {
    match obj {
        Scalar<Secp256k1>::SecretKey(secret) => {
            let mut bytes = secret.as_bytes().to_vec();
            bytes.resize(32, 0); // Pad with zeros to fixed size
            Ok(bytes)
        }
        Scalar<Secp256k1>::PublicKey(Public(point)) => {
            let mut encoded = [0u8; 65]; // Uncompressed format
            point.encode(&mut encoded, false)?;
            Ok(encoded.to_vec())
        }
        _ => Err("Unsupported Secp256k1 variant"),
    }
}

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
      
        let res = alice_ek.encrypt(to_bytes(a).as_ref(), None);
        let (c_a, _)=res.unwrap();
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
    // pub fn b(
    //     b: &Scalar<Secp256k1>,
    //     alice_ek: &EncryptionKey,
    //     m_a: MessageA,
    // ) -> Result<(Self, Scalar<Secp256k1>, BigInt, BigInt)> {
    //     // let beta_tag = BigInt::sample_below(&alice_ek.n);
    //     let randomness = BigInt::sample_below(&alice_ek.n);
    //     let (m_b, beta) = MessageB::b_with_predefined_randomness(
    //         b,
    //         alice_ek,
    //         m_a,
    //         &randomness,
    //     )?;

    //     Ok((m_b, beta, randomness))
    // }

    pub fn b(
        b: &Scalar<Secp256k1>,
        alice_ek: &EncryptionKey,
        m_a: MessageA,
        // randomness: &BigNumber,
    ) -> Result<(Self, Scalar<Secp256k1>)> {
        let beta_tag = sample_below(&alice_ek.n());
        let res = alice_ek.encrypt(beta_tag.to_bytes(), None);
        let (c_beta_tag,_) = res.unwrap();
        let beta_tag_fe = Scalar::<Secp256k1>::from(beta_tag.to_bigint());
        let b_byte = to_bytes(b);

        let b_bn = BigNumber::from_slice(b_byte.as_ref()); // need to be a bignumber
        let res1 = alice_ek.mul(&m_a.c, &b_bn);
        let b_c_a = res1.unwrap();
        let c_b = alice_ek.add(&b_c_a, &c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;


        Ok((
            Self {
                c: c_b.unwrap(),
                
            },
            beta,
        ))
    }

    pub fn get_alpha(
        &self,
        dk: &DecryptionKey,
        a: &Scalar<Secp256k1>,
    ) -> Result<(Scalar<Secp256k1>)> {
        let alice_share = dk.decrypt(&self.c.clone());
        // let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        // let g = Point::generator();
        
        let alpha = Scalar::<Secp256k1>::from(alice_share.to_bigint());
        // let g_alpha = g * &alpha;
        
        alpha
       
    }

}

pub fn generate_init() -> (EncryptionKey, DecryptionKey) {
  
  let sk = DecryptionKey::random();
  let dk = sk.unwrap();
  let ek = EncryptionKey::from(&dk);

  (ek, dk)
}

fn main() {
  let alice_input = Scalar::<Secp256k1>::random();
  let (ek_alice, dk_alice) = generate_init();
  let bob_input = Scalar::<Secp256k1>::random();
  let m_a = MessageA::a(&alice_input, &ek_alice);
  let (m_b, beta, _) = MessageB::b(&bob_input, &ek_alice, m_a).unwrap();
  let alpha = m_b
      .get_alpha(&dk_alice, &alice_input)
      .expect("wrong dlog or m_b");

  let left = alpha + beta;
  let right = alice_input * bob_input;
  assert_eq!(left, right);
}
