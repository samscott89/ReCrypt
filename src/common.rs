//! Commom functionality used across library

use std::str;
use ring::digest;

// "Debug print": prints var_name=value on a single line.
macro_rules! dprint {
    ($a:expr) => (println!("{:?}={:?}", stringify!($a),$a))
}

// Stolen from: http://ericsink.com/entries/rust1.html
// Seems surprisingly complicated.
// This fn is useful for debugging, so we permit it even if it's not being used.
pub fn to_hex_string(ba: &[u8]) -> String {
    let strs: Vec<String> = ba.iter()
        .map(|b| format!("{:02X}", b))
        .collect();
    strs.join(" ")
}

// Simplification for SHA256 hash
pub fn h(x: &[u8]) -> [u8; 32] {
    let mut ctx = digest::Context::new(&digest::SHA256);
    ctx.update(x);
    let mut hx: [u8; 32] = [0u8; 32];
    let res = ctx.finish();
    hx.copy_from_slice(res.as_ref());
    hx
}

// Pads a message to a multiple of block_len using PKCS7: pads the
// message with bytes that indicate the number of padding bytes
// that are added. 
// block_len must be [2,255] or this fn panic!s.
pub fn pad(msg: &mut Vec<u8>, block_len: usize) {
    // Check for illegal block_len.
    if block_len < 2 || block_len > 255 {
        panic!("Illegal block length ({:?}); must be between 1-255.", 
            block_len);
    }

    let rem = msg.len() % block_len;
    let pad_bytes : u8 = (block_len - rem) as u8;

    for _ in 0..pad_bytes {
        msg.push(pad_bytes);
    }
}

// Strips padding added by pad(). Returns None if the block has
// invalid padding.
pub fn remove_padding(mut msg: Vec<u8>) -> Option<Vec<u8>> {
    // Check for empty messages.
    if msg.len() == 0 {
        return None;
    }

    // Get the last byte and verify that it is not larger than the
    // the message.
    let pad_bytes = *msg.last().unwrap();
    if pad_bytes as usize > msg.len() {
        return None;
    }

    // Remove and validate the pad bytes.
    for _ in 0..pad_bytes {
        match msg.pop() {
            Some(v) if v == pad_bytes => continue,
            _ => return None
        }
    }
    Some(msg)
}


#[cfg(test)]
mod test {
    use rand;
    use super::h;

    #[test]
    fn hash_is_sane() {
        let x = [rand::random::<u8>(); 32];
        let y = h(&x);
        let z = h(&x);
        assert_eq!(y, z);
    }

}