use super::super::*;
use super::super::kh_prf::KhKey;
use ::io::*;

use std::io::{Read, Write, BufReader, BufWriter, Cursor};
use std::marker::PhantomData;
use std::ops::{Add,Sub};

/// `KSS` Scheme: KEM-DEM with Secret Sharing
///
/// This is an updatable encryption algorithm which meets some basic
/// indistinguishability and integrity notions.
///
/// Encryption is computed as:
/// ```text
/// E(k, m) = E(k, x+y || H(C))
///           y, C = E(x, m)
/// ```
///
/// `Kss` is defined over any generic pair of ciphers `A, B`. Which must be
/// authenticated encryption schemes in order to meet the security definitions.
///
/// `Kss` does not update the data encryption key when performing updates.
pub struct Kss<A, B>{
    kem_cipher: PhantomData<A>,
    dem_cipher: PhantomData<B>
}

/// ReCrypt updatable encryption algorithm
///
/// This updatable encryption scheme meets the strongest set of security notions.
/// On an update (`rekeygen` followed by `reencrypt`), the entire ciphertext
/// is "refreshed", resulting in an entirely refreshed ciphertext.
pub struct ReCrypt<A, B>{
    kem_cipher: PhantomData<A>,
    upenc_cipher: PhantomData<B>
}

impl<A: Cipher, B: Cipher> UpEnc for Kss<A,B>
    where for<'a> &'a B::K: Add<Output=B::K>, for<'a> &'a B::K: Sub<Output=B::K>
{
    // Type of the key variable
    type K = A::K;

    /* Generates a new, random key  */
    fn keygen() -> Self::K {
        A::keygen()
    }

    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen<In: Read, Out: Write>(k1: Self::K, k2: Self::K, ct_hdr: &mut In, token: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        // buf contains chi || tau
        A::decrypt(k1, ct_hdr, &mut buf)?;

        let y_new = B::keygen();
        let mut reader = Cursor::new(buf);
        let chi = B::K::read_key(&mut reader)?;
        let rk = &chi + &y_new;
        buf = Vec::new();
        rk.write_key(&mut buf)?;
        // buf should contain (chi' || tau)
        reader.read_to_end(&mut buf)?;
        // Write out to token y'
        y_new.write_key(token)?;
        // Write out to token E(k2, chi' || tau)
        A::encrypt(k2, &mut (&buf[..]), token)
    }

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct_hdr: &mut Out, ct_body: &mut Out) -> Result<()> {
        let x = B::keygen();
        let y = B::keygen();
        let chi = &x + &y;
        let mut buf = Vec::new();
        chi.write_key(&mut buf)?;
        y.write_key(ct_body)?;
        // Computes the hash as each ciphertext block is output
        let mut hash_ct = RwAndHash::new(ct_body);
        B::encrypt(x, pt, &mut hash_ct)?;
        let tau = hash_ct.finish();
        buf.write_all(tau.as_ref())?;
        A::encrypt(key, &mut (&buf[..]), ct_hdr)
    }

    fn reencrypt<In: Read, Out: Write>(rk: &mut In, _: &mut In, ct1_body: &mut In, ct2_hdr: &mut Out, ct2_body: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        let y_new = B::K::read_key(rk)?;
        rk.read_to_end(&mut buf)?;

        let mut reader = BufReader::new(ct1_body);
        let y = B::K::read_key(&mut reader)?;
        let mut writer = BufWriter::new(ct2_body);

        (&y + &y_new).write_key(&mut writer)?;

        // Write the rest of ct1 to ct2
        loop {
            let chunk = read_chunk(&mut reader, 128).unwrap();
            match chunk.len() {
                // EOF
                0 => break,

                // Expected block size
                _ => ()
            }

            writer.write_all(&chunk)?;
        }

        ct2_hdr.write_all(&buf)?;

        Ok(())
    }

    fn decrypt<In: Read, Out: Write>(key: Self::K, ct_hdr: &mut In, ct_body: &mut In, pt: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        A::decrypt(key, ct_hdr, &mut buf)?;

        let mut reader = Cursor::new(buf);
        let chi = B::K::read_key(&mut reader)?;
        buf = Vec::new();
        reader.read_to_end(&mut buf)?;

        let mut ct_reader = BufReader::new(ct_body);
        let y = B::K::read_key(&mut ct_reader)?;

        let mut ct_and_hash = RwAndHash::new(ct_reader);
        B::decrypt(&chi - &y, &mut ct_and_hash, pt)?;
        let tau_check = ct_and_hash.finish();
        if buf != tau_check.as_ref() {
            return Err("integrity check failed".into());
        }
        Ok(())
    }
}

impl<A: Cipher> UpEnc for ReCrypt<A, KhPrf>
    // where for<'a> &'a B::K: Add<Output=B::K>, for<'a> &'a B::K: Sub<Output=B::K>, B::K: Add<u64, Output=B::K>,
{
    // Type of the key variable
    type K = A::K;

    /* Generates a new, random key  */
    fn keygen() -> Self::K {
        A::keygen()
    }

    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen<In: Read, Out: Write>(k1: Self::K, k2: Self::K, ct_hdr: &mut In, token: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        // buf contains chi || tau
        A::decrypt(k1, ct_hdr, &mut buf)?;

        let x_new = KhPrf::keygen();
        let y_new = KhPrf::keygen();
        let mut reader = Cursor::new(buf);
        let chi = KhKey::read_key(&mut reader)?;
        let chi_new = &chi + &(&x_new + &y_new);
        buf = Vec::new();
        // buf contains chi'
        chi_new.write_key(&mut buf)?;

        let mut tau = Vec::new();
        reader.read_to_end(&mut tau)?;
        let tau_new = kh_prf::update_block(x_new.0, &tau, 0);
        buf.extend_from_slice(&tau_new);
        // buf should contain (chi' || tau')

        // Write out to token x', y'
        x_new.write_key(token)?;
        y_new.write_key(token)?;
        // Write out to token E(k2, chi' || tau)
        A::encrypt(k2, &mut (&buf[..]), token)
    }

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct_hdr: &mut Out, ct_body: &mut Out) -> Result<()> {
        let x = KhPrf::keygen();
        let y = KhPrf::keygen();
        let chi = &x + &y;
        let mut buf = Vec::new();
        chi.write_key(&mut buf)?;
        let mut hash_pt = RwAndHash::new(pt);

        // The key to encrypt tau uses 0 to avoid overlapping with encryption
        let prf_x = KhKey(x.0.clone(), 0);

        // Write y || C to the ciphertext body
        y.write_key(ct_body)?;
        KhPrf::encrypt(x, &mut hash_pt, ct_body)?;
        let hm = hash_pt.finish();

        // Encrypt tau into the header
        // Here the header contains chi || tau, where tau = h(m) + F(x, 0)
        // KhPrf::encrypt(prf_x, &mut hm.as_ref(), &mut buf)?;
        let tau = kh_prf::encrypt_block(prf_x.0, &hm.as_ref()[..31], 0);
        buf.extend_from_slice(&tau);
        // AEAD encrypt the header into the ciphertext header
        A::encrypt(key, &mut (&buf[..]), ct_hdr)
    }

    fn reencrypt<In: Read, Out: Write>(rk: &mut In, _: &mut In, ct1_body: &mut In, ct2_hdr: &mut Out, ct2_body: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        let x_new = KhKey::read_key(rk)?;
        let y_new = KhKey::read_key(rk)?;
        rk.read_to_end(&mut buf)?;
        // can directly read out rest of rk to header
        ct2_hdr.write_all(&buf).chain_err(|| "failed to write out")?;

        let mut reader = BufReader::new(ct1_body);
        let y = KhKey::read_key(&mut reader)?;
        let mut writer = BufWriter::new(ct2_body);

        (&y + &y_new).write_key(&mut writer)?;

        buf = Vec::new();
        x_new.write_key(&mut buf)?;

        // Write the rest of ct1 to ct2
        KhPrf::reencrypt(&mut (&buf[..]), &mut reader, &mut writer)

    }

    fn decrypt<In: Read, Out: Write>(key: Self::K, ct_hdr: &mut In, ct_body: &mut In, pt: &mut Out) -> Result<()> {
        let mut hdr_buf = Vec::new();
        A::decrypt(key, ct_hdr, &mut hdr_buf)?;

        let mut reader = Cursor::new(hdr_buf);
        let chi = KhKey::read_key(&mut reader)?;
        // reader.read_to_end(&mut buf)?;
        // KhPrf::decrypt()

        let mut ct_reader = BufReader::new(ct_body);
        let y = KhKey::read_key(&mut ct_reader)?;

        let x = &chi - &y;
        let prf_x = KhKey(x.0.clone(), 0);


        let mut pt_and_hash = RwAndHash::new(pt);
        KhPrf::decrypt(x, &mut ct_reader, &mut pt_and_hash)?;
        let tau_check = pt_and_hash.finish();
        let mut tau_buf = Vec::new();
        reader.read_to_end(&mut tau_buf)?;
        let tau = kh_prf::decrypt_block(prf_x.0, &tau_buf, 0)?;

        // This isn't great; the plaintext is already written to file before the
        // integrity is checked.
        if &tau[..] != &tau_check.as_ref()[..31] {
            return Err("integrity check failed".into());
        }
        Ok(())
    }
}
