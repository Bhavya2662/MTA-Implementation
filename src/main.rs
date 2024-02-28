use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
// use curv::BigInt;
// use paillier::traits::EncryptWithChosenRandomness;
// use paillier::{Add, Decrypt, Mul};
// use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
// use paillier::KeyGeneration;
// use libpaillier::{
//   unknown_order::BigNumber,
//   *
// };
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt};
use crate::lib::make_key_pair;
use rand::{Rng, thread_rng};
use curv::arithmetic::Converter;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use generic_array::{GenericArray, typenum::U32};
mod lib;
use lib::{PubKey, PrivKey };
// fn to_bytes(obj: &Scalar<Secp256k1>) -> Vec<u8> {
//     match obj {
//         Scalar::<Secp256k1>::SecretKey(secret) => {
//             let mut bytes = secret.as_bytes().to_vec();
//             bytes.resize(32, 0); // Pad with zeros to fixed size
//             bytes
//         }
//         Scalar::<Secp256k1>::PublicKey(point) => {
//             let mut encoded = [0u8; 65]; // Uncompressed format
//             point.encode(&mut encoded, false)?;
//             encoded.to_vec()
//         }
//         _ => Err("Unsupported Secp256k1 variant"),
//     }
// }

// fn sample_below(modulus: &BigNumber) -> BigNumber {
//   let mut rng = thread_rng();
//   let mut random_num = BigNumber::from(0);

//   // Loop until a number less than the modulus is generated
//   while random_num >= *modulus {
//       random_num = BigNumber::from(rng.gen_range(0, modulus.to_u64().unwrap_or(0)));
//   }

//   random_num
// }
fn scalar_to_string(scalar: &Scalar<Secp256k1>) -> String {
    let base_repr = scalar.to_bigint();
    base_repr.to_string()
  }
// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageA {
    pub c: BigInt,                     // paillier encryption
  }

// #[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MessageB {
    pub c: BigInt, // paillier encryption
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
        alice_ek: &PubKey,
    ) -> Self {
        
        let res = alice_ek.encrypt(&a.to_bigint());
        let res = match res {
            Some(value) => value,
            None => panic!("Unexpected None value"), // Replace with appropriate handling for `None`
          }
        
        // let c_a = EncryptionKey::encrypt(
        //     alice_ek,
        //     RawPlaintext::from(a.to_bigint()),
        //     &Randomness::from(randomness.clone()),
        // )
        // .0
        // .clone()
        // .into_owned();

        Self {
            c: res,// Option<BigInt>
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
        alice_ek: &PubKey,
        m_a: MessageA,
        // randomness: &BigNumber,
    ) -> (Self, Scalar<Secp256k1>) {
        // let res = alice_ek.n().to_string();
        let beta_tag = alice_ek.n;
        let c_beta_tag = alice_ek.encrypt(&beta_tag);
        let c_beta_tag = match c_beta_tag {
            Some(value) => value,
            None => panic!("Unexpected None value"), // Replace with appropriate handling for `None`
          }
        // let big_integer_beta_tag: BigInt = BigInt::from(&beta_tag);
        // let beta_tag_fe = Scalar::<Secp256k1>::from(&big_integer_beta_tag);//Bigint
        // let big_vec: Vec<u8> = beta_tag.to_bytes() // Convert this big number to a big-endian byte sequence vec<u8>, the sign is not included
        // let big_integer =  BigInt::from_bytes_be(Sign::Plus, &big_vec);  // convert vev<u8> to &[u8] 
        let beta_tag_fe = Scalar::<Secp256k1>::from(&beta_tag); // Bigint



        // let beta_tag_fe = Scalar::<Secp256k1>::from(&beta_tag);// Bigint
        

        let b_bn = b.to_bigint(); // need to be a bignumber
        let b_c_a = alice_ek.mult_two_plain_text(&m_a.c, &b_bn);
        let b_c_a = match b_c_a {
            Some(value) => value,
            None => panic!("Unexpected None value"), // Replace with appropriate handling for `None`
          }
        // let  = res1.unwrap();
        let c_b = alice_ek.add_two_plain_text(&b_c_a, &c_beta_tag);
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;


        Ok((
            Self {
                c: c_b,
                
            },
            beta,
        ))
    }

    pub fn get_alpha(
        &self,
        dk: &PrivKey,
        a: &Scalar<Secp256k1>,
    ) -> Scalar<Secp256k1>{
        let alice_share = dk.decrypt(&self.c.to_string());
        // let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        // let g = Point::generator();
        // let alice_bytes:&[u8] = &alice_share;
        // let a_s = BigInt::from_bytes_be(Sign::Plus, &alice_bytes);
        let alpha = Scalar::<Secp256k1>::from(alice_share);
        // let a_s = BigInt::from_bytes(&alice_share);
        // let alpha = Scalar::<Secp256k1>::from(a_s);
        // // let g_alpha = g * &alpha;
        
        alpha
       
    }

}

pub fn generate_init() -> (PubKey, PrivKey) {
  
  // Generate a key pair with a desired bit length for the keys (e.g., 2048)
  let key_pair = make_key_pair(2048).expect("Failed to generate key pair");

  // Extract the public and private keys from the key pair
  let public_key = key_pair.public_key;
  let private_key = key_pair.private_key;

  // Return the public and private keys as separate types
  (public_key, private_key)
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
