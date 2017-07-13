use super::super::*;
use ::io::*;

use std::fs::File;

use std::io::{Write,BufReader,BufWriter};

pub struct NullCipher;

impl Key for () {
    fn read_key<In: Read>(key_in: &mut In) -> Result<Self> {
        Ok(())
    }
    fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()> {
        Ok(())
    }
}

impl Cipher for NullCipher {
    // Type of the key variable
    type K = ();

    /* Generates a new, random key  */
    fn keygen() -> () {
        ()
    }
    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct: &mut Out) -> Result<()> {
        let mut reader = BufReader::new(pt);
        let mut writer = BufWriter::new(ct);

        let mut eof = false;
        while !eof {
            let block = read_chunk(&mut reader, 128).unwrap();
            if block.len() < 128 {
                eof = true;
            }
            try!(writer.write(&block));
        }
        Ok(())
    }

    fn decrypt<In: Read, Out: Write>(key: Self::K, ct: &mut In, pt: &mut Out) -> Result<()> {
        let mut reader = BufReader::new(ct);
        let mut writer = BufWriter::new(pt);

        loop {
            let chunk = read_chunk(&mut reader, 128).unwrap();

            let eof = match chunk.len() {
                0 => true,
                _ => false,
            };

            // Quit on EOF.
            if eof {
                break;
            }

            try!(write_pt(chunk, &mut writer, false));

        }
        Ok(())
    }
}

impl UpEncCtxtIndep for NullCipher {
    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen<Out: Write>(k1: Self::K, k2: Self::K, token: &mut Out) -> Result<()> {
        Ok(())
    }


    fn reencrypt<In1: Read, In2: Read, Out: Write>(rk: &mut In1, ct_old: &mut In2, ct_new: &mut Out) -> Result<()> {
        let mut reader = BufReader::new(ct_old);
        let mut writer = BufWriter::new(ct_new);

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
}
