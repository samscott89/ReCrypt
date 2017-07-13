use ring::{aead, rand};
use ring::rand::SecureRandom;

use super::*;

use std::ops::{Add, Sub};


use std::io::{BufReader, BufWriter};

// struct RingAE(&'static aead::Algorithm);
macro_rules! make_ring_ae {
    ($name:ident, $alg:expr, $keyname:ident) => (
        /// AE scheme wrapping the *ring* implementation
        pub struct $name;

        #[derive(Clone, Debug, PartialEq)]
        pub struct $keyname(Vec<u8>);

        impl Key for $keyname {
            fn read_key<In: Read>(key_in: &mut In) -> Result<Self> {
                let mut key = vec![0; $alg.key_len()];
                key_in.read_exact(&mut key).chain_err(|| "unable to read from file")?;
                Ok($keyname(key))
            }
            fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()> {
                key_out.write_all(&self.0).chain_err(|| "unable to write to file")
            }
        }

        impl<'a> Add for &'a $keyname {
            type Output = $keyname;

            fn add(self, other: &'a $keyname) -> $keyname {
                $keyname(self.0.iter().zip(other.0.iter()).map(|(a, b)| a^b).collect())
            }
        }

        impl<'a> Sub for &'a $keyname {
            type Output = $keyname;

            fn sub(self, other: &'a $keyname) -> $keyname {
                self + other
            }
        }  

        impl Cipher for $name {
            type K = $keyname;

            fn keygen() -> Self::K {
                let mut rand_bytes = vec![0u8; $alg.key_len()];
                let rng = rand::SystemRandom::new();
                rng.fill(&mut rand_bytes).expect("could not generate random bytes for keygen");
                $keyname(rand_bytes)
            }

            fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct: &mut Out) -> Result<()> {
                let mut ct = BufWriter::new(ct);
                let mut in_out = Vec::new();
                pt.read_to_end(&mut in_out)?;
                for _ in 0..$alg.tag_len() {
                    in_out.push(0);
                }

                let mut iv = [0u8; 12];
                let rng = rand::SystemRandom::new();
                rng.fill(&mut iv).expect("could not generate random bytes for IV");

                let key = aead::SealingKey::new(&$alg, &key.0).chain_err(|| "key invalid")?;
                let out_len = aead::seal_in_place(&key, &iv, &mut [], &mut in_out, $alg.tag_len()).chain_err(|| "encryption failed")?;

                ct.write_all(&iv).map_err(Error::from).chain_err(|| "unable to write to file")?;
                ct.write_all(&in_out[..out_len]).chain_err(|| "unable to write to file")?;

                Ok(())
            }
            fn decrypt<In: Read, Out: Write>(key: Self::K, ct: &mut In, pt: &mut Out) -> Result<()> {
                let mut ct = BufReader::new(ct);
                let mut iv = [0u8; 12];
                ct.read_exact(&mut iv).chain_err(|| "unable to read from file")?;

                let mut in_out = Vec::new();
                ct.read_to_end(&mut in_out).chain_err(|| "unable to read from file")?;

                let key = aead::OpeningKey::new(&$alg, &key.0).chain_err(|| "incorrect key")?;
                let out = aead::open_in_place(&key, &iv, &[], 0, &mut in_out).chain_err(|| "decryption failed")?;

                pt.write_all(&out).chain_err(|| "unable to write to file")
            }
        }


    )
}


make_ring_ae!(RingAes, aead::AES_128_GCM, AesKey128);
make_ring_ae!(RingChaCha, aead::CHACHA20_POLY1305, ChaChaKey128);
