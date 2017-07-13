use super::super::*;
use ::io::*;

use std::fs::{remove_file,File,OpenOptions};
use std::io::{Write,BufReader,BufWriter,SeekFrom,Seek};
use std::marker::PhantomData;

pub struct Naive<C>{
    cipher: PhantomData<C>
}

pub struct KemDem<C>{
    cipher: PhantomData<C>
}

impl<C: Cipher> UpEnc for Naive<C> {
    // Type of the key variable
    type K = C::K;

    /* Generates a new, random key  */
    fn keygen() -> Self::K {
        C::keygen()
    }

    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen<In: Read, Out: Write>(k1: Self::K, k2: Self::K, ct_hdr: &mut In, token: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        C::decrypt(k1, ct_hdr, &mut buf)?;
        C::encrypt(k2, &mut (&buf[..]), token)
    }

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct_hdr: &mut Out, _ct_body: &mut Out) -> Result<()> {
        // Encrypts the entire plaintext into the ciphertext "header".
        C::encrypt(key, pt, ct_hdr)
    }

    fn reencrypt<In: Read, Out: Write>(rk: &mut In, ct1_hdr: &mut In, ct1_body: &mut In, ct2_hdr: &mut Out, ct2_body: &mut Out) -> Result<()> {
        let mut reader = BufReader::new(rk);
        let mut writer = BufWriter::new(ct2_hdr);

        // Set ct2_hdr = token
        loop {
            let chunk = read_chunk(&mut reader, 128).unwrap();
            match chunk.len() {
                // EOF
                0 => break,

                // Expected block size
                _ => ()
            }

            try!(writer.write(&chunk));
        }
        Ok(())
    }
    fn decrypt<In: Read ,Out: Write>(key: Self::K, ct_hdr: &mut In, ct_body: &mut In, pt: &mut Out) -> Result<()> {
        C::decrypt(key, ct_hdr, pt)
    }
}


impl<C: Cipher> UpEnc for KemDem<C> {
    // Type of the key variable
    type K = C::K;

    /* Generates a new, random key  */
    fn keygen() -> C::K {
        C::keygen()
    }

    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen<In: Read, Out: Write>(k1: Self::K, k2: Self::K, ct_hdr: &mut In, token: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        C::decrypt(k1, ct_hdr, &mut buf)?;
        C::encrypt(k2, &mut (&buf[..]), token)
    }

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct_hdr: &mut Out, ct_body: &mut Out) -> Result<()> {
        let k_dem: C::K = C::keygen();
        let mut buf = Vec::new();
        k_dem.write_key(&mut buf)?;
        C::encrypt(key, &mut (&buf[..]), ct_hdr)?;
        C::encrypt(k_dem, pt, ct_body)
    }

    fn reencrypt<In: Read, Out: Write>(rk: &mut In, ct1_hdr: &mut In, ct1_body: &mut In, ct2_hdr: &mut Out, ct2_body: &mut Out) -> Result<()> {
        let mut tok_reader = BufReader::new(rk);
        let mut hdr_writer = BufWriter::new(ct2_hdr);
        let mut body_reader = BufReader::new(ct1_body);
        let mut body_writer = BufWriter::new(ct2_body);

        // Set ct2_hdr = token
        loop {
            let chunk = read_chunk(&mut tok_reader, 128).unwrap();
            match chunk.len() {
                // EOF
                0 => break,

                // Expected block size
                _ => ()
            }

            try!(hdr_writer.write(&chunk));
        }
        // Set ct2_body = ct1_body
        loop {
            let chunk = read_chunk(&mut body_reader, 128).unwrap();
            match chunk.len() {
                // EOF
                0 => break,

                // Expected block size
                _ => ()
            }

            try!(body_writer.write(&chunk));
        }
        Ok(())
    }
    fn decrypt<In: Read ,Out: Write>(key: Self::K, ct_hdr: &mut In, ct_body: &mut In, pt: &mut Out) -> Result<()> {
        let mut buf = Vec::new();
        C::decrypt(key, ct_hdr, &mut buf);
        let k_dem = C::K::read_key(&mut (&buf[..]))?;
        C::decrypt(k_dem, ct_body, pt)
    }
}
