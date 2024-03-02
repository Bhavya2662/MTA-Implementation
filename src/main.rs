#![allow(unused_imports)]
#![allow(non_snake_case)]
#![allow(unused_variables)]
#![allow(unused_parens)]
use curv::arithmetic::traits::Samplable;
use curv::elliptic::curves::{secp256_k1::Secp256k1, Point, Scalar};
use std::ops::Add;
use std::ops::Mul;

// use paillier::traits::EncryptWithChosenRandomness;
// use paillier::{Add, Decrypt, Mul};
// use paillier::{DecryptionKey, EncryptionKey, Paillier, Randomness, RawCiphertext, RawPlaintext};
// use paillier::KeyGeneration;
// use libpaillier::{
//   unknown_order::BigNumber,
//   *
// };

use std::str::FromStr;
use num_bigint::{BigInt, BigUint, RandBigInt, ToBigInt, Sign};
use curv::BigInt as curvBigInt;

use crate::lib::make_key_pair;
use rand::{Rng, thread_rng};
use curv::arithmetic::Converter;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use generic_array::{GenericArray, typenum::U32};
mod lib;
use lib::{PubKey, PrivKey };


use num_traits::One;
use num_traits::Zero;
fn sample_below(b: &BigInt) -> BigInt {
    let mut rng = rand::thread_rng();
    let zero = num_bigint::BigInt::zero();
    loop {
        let r = rng.gen_bigint_range(&zero, b);
        if &r < b {
            return r;
        }
    }
}
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

// fn convert_curv_to_num_bigint(curv_bigint: &NumBigInt) -> BigInt {
//     let mut num_bigint = BigInt::from(0);
//     let curv_bigint_bytes = curv_bigint.to_bytes();
//     for byte in curv_bigint_bytes.iter().rev() {
//         num_bigint = num_bigint << 8;
//         num_bigint += BigInt::from(*byte);
//     }
//     num_bigint
// }
// fn convert_num_bigint_to_curv_bigint(num_bigint: BigInt) -> curvBigInt {
//     let mut bytes = num_bigint.to_bytes_be();
    
//     let bytes_without_sign = &mut bytes.1;
//     bytes_without_sign.reverse();
//     curvBigInt::from_bytes(&bytes_without_sign)
// }
fn convert_num_bigint_to_curv_bigint(num_bigint: &BigInt) -> curvBigInt {
    let mut bytes = num_bigint.to_str_radix(16);
    let curvbigint = curvBigInt::from_hex(&bytes);
    curvbigint.unwrap()
    // let bytes_without_sign = &mut bytes.1;
    // bytes_without_sign.reverse();
    // curvBigInt::from_bytes(&bytes_without_sign)
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
        // dbg!(&a.to_bigint());
        let hex_alice_bigint = a.to_bigint().to_hex(); //fixed

        //let biggg = BigInt::from_str(&str_alice_bigint).unwrap();
        //dbg!(&biggg);
        // dbg!(&hex_alice_bigint);
        let bigint_from_hex = BigInt::parse_bytes(hex_alice_bigint.as_bytes(), 16).unwrap();
        println!("BigInt from hex: {}", bigint_from_hex); //correct value of bigint
        // dbg!(&bigint_from_hex);
        //dbg!(&convert_curv_to_num_bigint(&a.to_bigint()));
        //let res = alice_ek.encrypt(&a.to_bigint());
        //let res = alice_ek.encrypt(&convert_curv_to_num_bigint(&a.to_bigint()));

        // have to convert curv::BigInt to num_bigint without str use. 
        let res = alice_ek.encrypt(&bigint_from_hex); //error here. FIXED
        // let res = match res {
        //     Some(value) => value,
        //     None => panic!("Unexpected None value"), // Replace with appropriate handling for `None`
        //   };
        
        // let c_a = EncryptionKey::encrypt(
        //     alice_ek,
        //     RawPlaintext::from(a.to_bigint()),
        //     &Randomness::from(randomness.clone()),
        // )
        // .0
        // .clone()
        // .into_owned();

        Self {
            c: res.unwrap(),// Option<BigInt>
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
        let beta_tag = sample_below(&alice_ek.n); // random bigint
        dbg!(&beta_tag);
        let c_beta_tag = alice_ek.encrypt(&beta_tag); //error here. This will fail cause essentially, m given is same as alice_ek's n.
        let c_beta_tag = match c_beta_tag {
            Some(value) => value,
            None => panic!("Unexpected None value"), // Replace with appropriate handling for `None`
          };
        // let big_integer_beta_tag: BigInt = BigInt::from(&beta_tag);
        // let beta_tag_fe = Scalar::<Secp256k1>::from(&big_integer_beta_tag);//Bigint
        // let big_vec: Vec<u8> = beta_tag.to_bytes() // Convert this big number to a big-endian byte sequence vec<u8>, the sign is not included
        // let big_integer =  BigInt::from_bytes_be(Sign::Plus, &big_vec);  // convert vev<u8> to &[u8] 
        
        //Error!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
        // let str_bigint = String::from(&beta_tag.to_string());
        // let scalar_bitint_beta_tag: &[u8] = str_bigint.as_bytes(); //fixed
        let res = convert_num_bigint_to_curv_bigint(&beta_tag);
        dbg!(&res);
        dbg!(Scalar::<Secp256k1>::from(&res));
        let  beta_tag_fe = Scalar::<Secp256k1>::from(res);
        // let beta_tag_fe = Scalar::<Secp256k1>::from_bytes(&scalar_bitint_beta_tag); // Bigint

        //let beta_tag_fe = Scalar::<Secp256k1>::from(&beta_tag);// Bigint

        let b_bn = b.to_bigint(); // need to be a bignumber

        let string_bigint_bca = String::from(b_bn.to_string());
        let num_bigint_bca = BigInt::from_bytes_be(Sign::Plus, string_bigint_bca.as_bytes());

        let b_c_a = alice_ek.mult_two_plain_text(&m_a.c, &num_bigint_bca); //fixed
        // let beta_tag_fe = match beta_tag_fe {
        //     Some(value) => value,
        //     None => panic!("Unexpected None value"), // Replace with appropriate handling for `None`
        //   };
        // let  = res1.unwrap();
        let c_b = alice_ek.add_two_plain_text(&b_c_a.unwrap(), &c_beta_tag);
        
        let beta = Scalar::<Secp256k1>::zero() - &beta_tag_fe;
        // let beta = match beta_tag_fe {
        //     Ok(value) => Scalar::<Secp256k1>::zero() - value,
        //     Err(err) => panic!("Error: {:?}", err),
        // };

        ((
            Self {c: c_b.unwrap()},
            beta,
        ))
    }

    pub fn get_alpha(
        &self,
        dk: &PrivKey,
        a: &Scalar<Secp256k1>,
    ) -> Scalar<Secp256k1>{


        let alice_share = dk.decrypt(&self.c.clone()).unwrap();
        // let alice_share = Paillier::decrypt(dk, &RawCiphertext::from(self.c.clone()));
        // let g = Point::generator();

        // let str_bigint_alice_sh = String::from(&alice_share.to_string());
        // let scalar_bitint_alice_sh: &[u8] = str_bigint_alice_sh.as_bytes();
        let res = convert_num_bigint_to_curv_bigint(&alice_share);
        //let alice_bytes:&[u8] = &alice_share.unwrap();
        //let a_s = BigInt::from_bytes_be(Sign::Plus, &alice_bytes);
        let alpha = Scalar::<Secp256k1>::from(&res);
        // let a_s = BigInt::from_bytes(&alice_share);
        // let alpha = Scalar::<Secp256k1>::from(a_s);
        // // let g_alpha = g * &alpha;
        
        alpha
       
    }

}

pub fn generate_init() -> (PubKey, PrivKey) {
  
  // Generate a key pair with a desired bit length for the keys (e.g., 2048)
  let key_pair = make_key_pair(256).expect("Failed to generate key pair");

  // Extract the public and private keys from the key pair
//   let public_key = key_pair.pk; 
//   let private_key = key_pair;

//   // Return the public and private keys as separate types

   let (private_key, public_key)= key_pair.get_keys();
   (public_key.clone(), private_key.clone())

}

fn main() {
  let alice_input = Scalar::<Secp256k1>::random();
  let (ek_alice, dk_alice) = generate_init();
    //dbg!(&ek_alice);
    //dbg!(&dk_alice);
    let ek_a = ek_alice.clone();
    let q_num = ek_a.n;
    let q = convert_num_bigint_to_curv_bigint(&q_num);

  let bob_input = Scalar::<Secp256k1>::random();
  let m_a = MessageA::a(&alice_input, &ek_alice);

  let (m_b, beta) = MessageB::b(&bob_input, &ek_alice, m_a);
let beta_bn = beta.to_bigint();
let beta_bnn = beta_bn % &q;
let beta = Scalar::<Secp256k1>::from(beta_bnn);
  let alpha = m_b
      .get_alpha(&dk_alice, &alice_input);
let alpha_bn = alpha.to_bigint();
let alpha_bnn = alpha_bn % &q;
let alpha = Scalar::<Secp256k1>::from(alpha_bnn);

//   let left = alpha + beta;
let res1 = alpha+beta;
let res1_bn = res1.to_bigint();

let left  = Scalar::<Secp256k1>::from(res1_bn % &q);

let res2 = alice_input * bob_input;
let res2_bn = res2.to_bigint();
//   let right = alice_input * bob_input;
let right = Scalar::<Secp256k1>::from(res2_bn % &q) ;

  assert_eq!(left, right);

// Encrytion and decryption testing
// let plaintext = BigInt::from(1234);
//         let (public_key, private_key) = generate_init();
        
//         let ciphertext = public_key.encrypt(&plaintext);
//         let decrypted = private_key.decrypt(&ciphertext.unwrap()).unwrap();
        
//         assert_eq!(plaintext, decrypted);
// let plaintext_a = BigInt::from(1234);
//     let plaintext_b = BigInt::from(5678);
//     let (public_key, private_key) = generate_init();
    
//     let ciphertext_a = public_key.encrypt(&plaintext_a).unwrap();
//     let ciphertext_b = public_key.encrypt(&plaintext_b).unwrap();
    
//     let sum_ciphertext = public_key.add(&ciphertext_a, &ciphertext_b).unwrap();
//     let sum_decrypted = private_key.decrypt(&sum_ciphertext).unwrap();
    
//     let sum_plaintext = plaintext_a + plaintext_b;
    
//     assert_eq!(sum_plaintext, sum_decrypted);
}