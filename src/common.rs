//! Commom functionality used across library
use std::iter::IntoIterator;

#[macro_export]
macro_rules! h {
    ( $( $x:expr ),* ) => (
        {   
            use ring::digest;
            let mut ctx = digest::Context::new(&digest::SHA256);
            $(
                ctx.update($x);
            )*
            ctx.finish()
        }
    )
}

// // Simplification for SHA256 hash
// pub fn h<'a, I: IntoIterator<Item=&'a [u8]>>(x: I) -> [u8; 32] {
//     let mut ctx = digest::Context::new(&digest::SHA256);
//     x.for_each(|x| ctx.update(x));
//     let mut hx: [u8; 32] = [0u8; 32];
//     let res = ctx.finish();
//     hx.copy_from_slice(res.as_ref());
//     hx
// }

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

    #[test]
    fn hash_is_sane() {
        let x = [rand::random::<u8>(); 32];
        let y = h!(&x);
        let z = h!(&x);
        assert_eq!(y.as_ref(), z.as_ref());
    }

}