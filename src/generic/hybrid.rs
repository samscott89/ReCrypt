use super::super::*;
use ::io::*;

use std::io::{Read, Write, BufReader, BufWriter, Cursor};
use std::marker::PhantomData;
use std::ops::{Add,Sub};

pub struct Kss<A, B>{
    kem_cipher: PhantomData<A>,
    dem_cipher: PhantomData<B>
}

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
        let mut hash_pt = RwAndHash::new(pt);
        y.write_key(ct_body)?;
        B::encrypt(x, &mut hash_pt, ct_body)?;
        let tau = hash_pt.finish();
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

        let mut pt_and_hash = RwAndHash::new(pt);
        B::decrypt(&chi - &y, &mut ct_reader, &mut pt_and_hash)?;
        let tau_check = pt_and_hash.finish();
        if buf != tau_check.as_ref() {
            return Err("integrity check failed".into());
        }
        Ok(())
    }
}

impl<A: Cipher, B: UpEncCtxtIndep> UpEnc for ReCrypt<A,B>
    where for<'a> &'a B::K: Add<Output=B::K>, for<'a> &'a B::K: Sub<Output=B::K>, B::K: Add<u64, Output=B::K>,
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

        let x_new = B::keygen();
        let y_new = B::keygen();
        let mut reader = Cursor::new(buf);
        let chi = B::K::read_key(&mut reader)?;
        let rk = &chi + &(&x_new + &y_new);
        buf = Vec::new();
        rk.write_key(&mut buf)?;

        let mut x_buf = Vec::new();
        x_new.write_key(&mut x_buf)?;
        B::reencrypt(&mut (&x_buf[..]), &mut reader, &mut buf)?;
        // buf should contain (chi' || tau)


        // Write out to token x', y'
        x_new.write_key(token)?;
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
        let mut hash_pt = RwAndHash::new(pt);
        y.write_key(ct_body)?;

        // Offset the counter so it doesn't overlap with the encryption of the hash
        let outer_x = x.clone() + 127;
        B::encrypt(outer_x, &mut hash_pt, ct_body)?;
        let hm = hash_pt.finish();
        // buf.write_all(tau.as_ref())?;
        // Here the header contains chi || tau, where tau = h(m) + F(x, 0)
        B::encrypt(x, &mut hm.as_ref(), &mut buf)?;
        A::encrypt(key, &mut (&buf[..]), ct_hdr)
    }

    fn reencrypt<In: Read, Out: Write>(rk: &mut In, _: &mut In, ct1_body: &mut In, ct2_hdr: &mut Out, ct2_body: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        let x_new = B::K::read_key(rk)? + 127;
        let y_new = B::K::read_key(rk)?;
        rk.read_to_end(&mut buf)?;
        // can directly read out rest of rk to header
        ct2_hdr.write_all(&buf).chain_err(|| "failed to write out")?;

        let mut reader = BufReader::new(ct1_body);
        let y = B::K::read_key(&mut reader)?;
        let mut writer = BufWriter::new(ct2_body);

        (&y + &y_new).write_key(&mut writer)?;

        buf = Vec::new();
        x_new.write_key(&mut buf)?;

        // Write the rest of ct1 to ct2
        B::reencrypt(&mut (&buf[..]), &mut reader, &mut writer)

    }

    fn decrypt<In: Read, Out: Write>(key: Self::K, ct_hdr: &mut In, ct_body: &mut In, pt: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        A::decrypt(key, ct_hdr, &mut buf)?;

        let mut reader = Cursor::new(buf);
        let chi = B::K::read_key(&mut reader)?;
        buf = Vec::new();
        // reader.read_to_end(&mut buf)?;
        // B::decrypt()

        let mut ct_reader = BufReader::new(ct_body);
        let y = B::K::read_key(&mut ct_reader)?;

        let x = &chi - &y;
        let outer_x = x.clone() + 127;

        let mut pt_and_hash = RwAndHash::new(pt);
        B::decrypt(outer_x, &mut ct_reader, &mut pt_and_hash)?;
        let tau_check = pt_and_hash.finish();
        B::decrypt(x, &mut reader, &mut buf)?;
        // This isn't great; the plaintext is already written to file before the
        // integrity is checked.
        if buf != tau_check.as_ref() {
            return Err("integrity check failed".into());
        }
        Ok(())
    }
}
