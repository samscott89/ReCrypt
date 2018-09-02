use curve25519_dalek;
use curve25519_dalek::curve::ExtendedPoint;
use curve25519_dalek::scalar::Scalar;

use rand::os::OsRng;

use std::io::{Read,Write,BufReader,BufWriter};
use std::ops::{Add, Sub};

use super::*;
use common::{h, pad};
use io::*;

/// Encryption using a key-homomorphic PRF.
///
/// This is the generic "counter-mode" encryption: `E(k, m) = (m_1 + F(k, 1), ...)`. 
pub struct KhPrf;

#[derive(Clone, Debug, PartialEq)]
pub struct KhKey(pub Scalar, pub u64);

impl Key for KhKey {
    fn read_key<In: Read>(key_in: &mut In) -> Result<Self> {
        let mut bytes = [0u8; 32];
        let mut ctr = [0u8; 1];
        key_in.read_exact(&mut bytes)?;
        key_in.read_exact(&mut ctr)?;
        Ok(KhKey(Scalar(bytes), ctr[0] as u64))
    }
    fn write_key<Out: Write>(&self, key_out: &mut Out) -> Result<()> {
        key_out.write_all(&(&self.0).0).chain_err(|| "failed writing to file")?;
        key_out.write_all(&[self.1 as u8]).chain_err(|| "failed writing to file")
    }
}

impl<'a> Add for &'a KhKey {
    type Output = KhKey;

    fn add(self, other: Self) -> Self::Output {
        KhKey(&self.0 + &other.0, self.1)
    }
}

impl Add<u64> for KhKey {
    type Output = KhKey;

    fn add(self, other: u64) -> KhKey {
        KhKey(self.0, self.1 + other)
    }
}

impl<'a> Sub for &'a KhKey {
    type Output = KhKey;

    fn sub(self, other: Self) -> Self::Output {
        KhKey(&self.0 - &other.0, self.1)
    }
}

impl Cipher for KhPrf {
    // The key is a random scalar, and the starting counter
    type K = KhKey;

     // Generate a random encryption key
    fn keygen() -> Self::K {
        let mut rng = OsRng::new().unwrap();
        KhKey(Scalar::random(&mut rng), 1)
    }

    fn encrypt<In: Read, Out: Write>(key: Self::K, pt: &mut In, ct: &mut Out) -> Result<()> {
        let mut ctr = key.1;
        let pt_block_size = 31;
     
        let mut reader = BufReader::new(pt);
        let mut writer = BufWriter::new(ct);

        let mut eof = false;
        while !eof {
            let mut block = read_chunk(&mut reader, pt_block_size).unwrap();

            // Pad if it's not a full block.
            if block.len() < pt_block_size {
                pad(&mut block, pt_block_size);
                eof = true;
            }

            let ct_block = encrypt_block(key.0, &block, ctr);
            writer.write_all(&ct_block)?;

            // Increment ctr for each block
            ctr += 1;
        }
        Ok(())
    }

    fn decrypt<In: Read, Out: Write>(key: Self::K, ct: &mut In, pt: &mut Out) -> Result<()> {
        let mut reader = BufReader::new(ct);
        let mut writer = BufWriter::new(pt);
        let ct_block_size = 32;
        let mut ctr = key.1;

        let mut prev_pt_block = Vec::new();
        loop {
            let chunk = read_chunk(&mut reader, ct_block_size).unwrap();

            // Ciphertext files are expected to be exact multiples of CT_BLOCK_SIZE.
            // Check for EOF or other unexpected block sizes.
            let eof = match chunk.len() {
                0 => true,
                n if n != ct_block_size => { return Err("incorrect block size".into()); },
                _ => false,
            };

            // Now that we know whether this is the last chunk of the file
            // (i.e. does this chunk need padding removed), we can write
            // it to the file.
            write_pt(prev_pt_block, &mut writer, eof)?;

            // Quit on EOF.
            if eof {
                break;
            }

            // Decode the EcPoint and decrypt.
            // let point = EcPoint::from_bytes(&chunk).unwrap();
            prev_pt_block = decrypt_block(key.0, &chunk, ctr)?;

            // Increment ctr for each block
            ctr += 1;
        }
        Ok(())
    }
}

impl UpEncCtxtIndep for KhPrf {
    fn reencrypt<In1: Read, In2: Read, Out: Write>(rk_file: &mut In1, ct1: &mut In2, ct2: &mut Out) 
            -> Result<()> {
        let mut reader = BufReader::new(ct1);
        let mut writer = BufWriter::new(ct2);
        let ct_block_size = 32;

        // Read the re-keying token from the file.
        let rk_token = Self::K::read_key(rk_file)?;

        // // Read the counter from the file.
        // let mut ctr_bytes = [0u8;8];
        // match reader.read(&mut ctr_bytes) {
        //     Ok(8) => (),
        //     _ => return invalid_file("Failed to read counter from file. File too small."),
        // };

        // Write the counter to the ct2 and convert it to a u64 to perform 
        // updates.
        // try_or_panic!(writer.write(&ctr_bytes));
        // let mut ctr = u8_to_u64(ctr_bytes);
        let mut ctr = rk_token.1;
        
        // Read and update each ciphertext block of the file.
        loop {
            let chunk = read_chunk(&mut reader, ct_block_size).unwrap();
            match chunk.len() {
                // EOF
                0 => break,

                // Woah, buddy.
                n if n != ct_block_size => return Err("incorrect block size".into()),

                // Expected block size
                _ => ()
            }

            // Decode the EcPoint and update.
            // let point = EcPoint::from_bytes(&chunk).unwrap();

            let bytes = update_block(rk_token.0, &chunk, ctr);

            // Write the newpoint to the output file.
            // let bytes = newpoint.serialize();
            writer.write_all(&bytes[..])?;

            ctr += 1;
        }
        Ok(())
    }
    
    
    // Generate an update rk_token that coverts ciphertexts from k1 to k2
    fn rekeygen<Out: Write>(k1: Self::K, k2: Self::K, rk_out: &mut Out) -> Result<()> {
        // let rk = rekey_token(k1, k2);
        let rk = &k2 - &k1;
        rk.write_key(rk_out)
    }
}


// Encrypt a single block of raw plaintext
pub fn encrypt_block(key: Scalar, msg: &[u8], ctr: u64) -> Vec<u8> {
    let m = encode_point(&msg);

    let c = encrypt_point(key, m, ctr);

    // c.serialize()
    c.compress_edwards().as_bytes().to_vec()
}

// big endian u64 to u8 array
#[inline]
pub fn u64_to_u8(v: u64) -> [u8; 8] {
    [
        (v >> 56) as u8,
        (v >> 48) as u8,
        (v >> 40) as u8,
        (v >> 32) as u8,
        (v >> 24) as u8,
        (v >> 16) as u8,
        (v >> 8) as u8,
        v as u8,
    ]
}

fn prf(key: Scalar, ctr: u64) -> ExtendedPoint {
    (&key * &hash_to_group(ctr)).mult_by_cofactor()
}

// Encrypt a single EcPoint.
pub fn encrypt_point(key: Scalar, msg: ExtendedPoint, ctr: u64) -> ExtendedPoint {
    // C::prf(key, &u64_to_u8(ctr)) + msg
    &prf(key, ctr) + &msg
}

pub fn update_block(rk: Scalar, ct_block: &[u8], ctr: u64) -> Vec<u8> {
    debug_assert_eq!(ct_block.len(), 32);
    let mut point_bytes = [0u8; 32];
    point_bytes.copy_from_slice(&ct_block);
    let point = curve25519_dalek::curve::CompressedEdwardsY(point_bytes);
    let point = point.decompress().unwrap();
    let newpoint = update_point(rk, point, ctr);

    newpoint.compress_edwards().as_bytes().to_vec()
}

// Updates a single ciphertext block/point
pub fn update_point(rk: Scalar, block: ExtendedPoint, ctr: u64) -> ExtendedPoint {
    &prf(rk, ctr) + &block
}

// Decrypts a single block of ciphertext
pub fn decrypt_block(key: Scalar, ct_block: &[u8], ctr: u64) -> Result<Vec<u8>> {
    // let point = deserialize(&ct_block).unwrap();
    debug_assert_eq!(ct_block.len(), 32);
    let mut point_bytes = [0u8; 32];
    point_bytes.copy_from_slice(&ct_block);
    let point = curve25519_dalek::curve::CompressedEdwardsY(point_bytes);
    let point = point.decompress().unwrap();
    decode_point(decrypt_point(key, point, ctr))
}

// Decrypts a single EcPoint
pub fn decrypt_point(key: Scalar, ct: ExtendedPoint, ctr: u64) -> ExtendedPoint {
    &ct - &prf(key, ctr)

}


pub fn encode_point(bytes: &[u8]) -> ExtendedPoint {
    debug_assert_eq!(bytes.len(), 31);
    let mut point_bytes = [0u8; 32];
    point_bytes[..31].copy_from_slice(bytes);
    let enc  = ExtendedPoint::from_uniform_representative(&point_bytes);
    enc
}
pub fn decode_point(point: ExtendedPoint) -> Result<Vec<u8>> {
    // point.compress_edwards().as_bytes()[1..].to_vec()
    // println!("Point to decode:{:?}", point); 
    let decoded = point.to_uniform_representative().unwrap();
    if decoded[31] != 0 {
        return Err("invalid point decoding".into());
    }
    Ok(decoded[..31].to_vec())
}

pub fn hash_to_group(ctr: u64) -> ExtendedPoint {
    let mut bytes = u64_to_u8(ctr);
    let hash = h(&bytes);
    let p1 = encode_point(&hash[1..]);
    bytes[0] = 0xff;
    let mut hash = h(&bytes);
    hash[31] &= 0x7f;
    let p2 = Scalar(hash);
    &p1 + &(&p2 * &curve25519_dalek::constants::ED25519_BASEPOINT_TABLE)
    // // This already maps the full 32-bytes to group points.
}