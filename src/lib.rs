/// ReCrypt - Key Rotation for Authenticated Encryption
///
/// This is a research prototype and should never be used for important data
///
///
/// This library contains some prototype implementations of updatable encryption
/// schemes. See https://eprint.iacr.org/2017/527 for more details.
///
/// There are 2 main building blocks:
///   - Authenticated encryption schemes (AES and ChaCha from *ring*).
///   - Key-homomorphic PRF (using `curve25519_dalek`)
///
/// These can be composed to construct updatable encryption.
///
/// The "naive" schemes are `Naive` and `KemDem`, which do not meet our security
/// definitions and are included for reference.
///
/// The updatable schemes are `Kss` and `ReCrypt`. These can be found in the
/// [generic](generic/) module.
///
/// We also define the `UpEnc` and `UpEncCtxtIndep` traits, which match the definitions
/// given in our text.

extern crate curve25519_dalek;
#[macro_use]
extern crate error_chain;
extern crate rand;
extern crate ring;

use std::fmt::Debug;
use std::io::{Read, Write};

/// ReCrypt errors.
pub mod errors {
    error_chain!{
        foreign_links {
            Io(::std::io::Error);
        }
    }
}

use errors::*;

#[macro_use]
pub mod common;
pub mod generic;
mod io;
mod kh_prf;
pub mod profile;
mod ring_ae;

pub use kh_prf::KhPrf;
pub use ring_ae::{RingAes, RingChaCha};
// pub use recrypt::ReCrypt;

/// A generic cipher trait.
///
/// Main algorithms are the typical `(KeyGen, Encrypt, Decrypt)` tuple,
/// with `read_key/write_key` for IO help.
pub trait Cipher {
    type K: Key;

    fn keygen() -> Self::K;

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct: &mut Out) -> Result<()>;
    fn decrypt<In: Read, Out: Write>(key: Self::K, ct: &mut In, pt: &mut Out) -> Result<()>;    
}

/// Trait for a ciphertext-independent updatable encryption scheme.
pub trait UpEncCtxtIndep: Cipher {
    /* Writes a re-keying token to a file for a pair of keys */
    fn rekeygen<Out: Write>(k1: Self::K, k2: Self::K, token: &mut Out) -> Result<()>;
    fn reencrypt<In1: Read, In2: Read, Out: Write>(rk: &mut In1, ct_old: &mut In2, ct_new: &mut Out) -> Result<()>;
}


/// Trait for an updatable encryption scheme.
pub trait UpEnc {
    // Type of the key variable
    type K: Key;

    /* Generates a new, random key  */
    fn keygen() -> Self::K;

    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen<In: Read, Out: Write>(k1: Self::K, k2: Self::K, ct_hdr: &mut In, token: &mut Out) -> Result<()>;

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct_hdr: &mut Out, ct_body: &mut Out) -> Result<()>;
    fn reencrypt<In: Read, Out: Write>(rk: &mut In, ct1_hdr: &mut In, ct1_body: &mut In, ct2_hdr: &mut Out, ct2_body: &mut Out) -> Result<()>;
    fn decrypt<In: Read, Out: Write>(key: Self::K, ct_hdr: &mut In, ct_body: &mut In, pt: &mut Out) -> Result<()>;
}

/// Trait encapsulating some common functionality needed for the keys.
pub trait Key: PartialEq + Clone + Debug + Sized {
    fn read_key<In: Read>(key_in: &mut In) -> Result<Self>;
    fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()>;
}
