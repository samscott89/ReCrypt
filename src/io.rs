use common::remove_padding;
use super::Error;

use std;
use std::io::{Write, Read};
use std::fs::{File,OpenOptions};
use std::path::Path;

use ring::digest;

// Reads a chunk of up to len bytes. Any return value smaller than
// len indicates EOF has been reached.
pub fn read_chunk(reader: &mut Read, len: usize) -> Result<Vec<u8>, Error> {
    let mut result = vec![0u8; len];

    // Number of bytes read so far, used as an index into result.
    let mut i = 0; 
    while i < len {
        // Read from the file.
        let n = match reader.read(&mut result[i..len]) {
            Ok(n) => n,
            Err(e) => return Err(e.into())
        };
        i += n;

        // println!("read {:?} bytes", n);

        // Ok(0) is EOF.
        if n == 0 {
            break;
        }
    }
    // println!("returning {:?} bytes", i);
    // In case the total bytes read is smaller than expected,
    // (EOF or last block in the file).
    result.truncate(i);
    // println!("returning {:?} bytes", result.len());
    Ok(result)
}

// Writes bytes to a writer (unless bytes is empty). If padded = true,
// and bytes is non-empty, padding is first removed from bytes.
pub fn write_pt(block: Vec<u8>, writer: &mut Write, padded: bool) 
        ->  Result<(), Error> {
    // Don't bother with empty input.
    if block.len() == 0 {
        return Ok(());
    }

    // Remove padding, if requested.
    let byte_vec = match padded {
        false => block, 
        true => match remove_padding(block) {
            // Bail out if no bytes are left after padding removed.
            None => { return Ok(()); },
            Some(b) => b
        }
    };

    // Write the bytes to the file.
    try!(writer.write_all(&byte_vec[..]));
    Ok(())
}

pub fn open_file<P: AsRef<Path>>(path: P) -> File {
    OpenOptions::new().read(true).write(true).create(true).open(path).unwrap()
}

pub struct RwAndHash<T> {
    hash: digest::Context,
    rw: T,
}

impl<T> RwAndHash<T> {
    pub fn new(inner: T) -> Self {
        RwAndHash {
            hash: digest::Context::new(&digest::SHA256),
            rw: inner,
        }
    }

    pub fn finish(self) -> digest::Digest {
        self.hash.finish()
    }
}

impl<T: Read> Read for RwAndHash<T> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let num = self.rw.read(buf)?;
        self.hash.update(&buf[..num]);
        Ok(num)
    }
}

impl<T: Write> Write for RwAndHash<T> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let num = self.rw.write(buf)?;
        self.hash.update(&buf[..num]);
        Ok(num)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.rw.flush()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use ::common::*;

    #[test]
    fn test_hash_and_read() {
        let mut buf = Vec::new();
        let input = [0xfa; 128];
        let mut rh = RwAndHash::new(&input[..]);
        rh.read_to_end(&mut buf);
        let digest = rh.finish();
        assert_eq!(digest.as_ref(), h!(&input).as_ref());
        assert_eq!(buf, &input[..]);
    }

    #[test]
    fn test_hash_and_write() {
        let mut buf = Vec::new();
        let input = [0xfa; 128];
        {
            let mut wh = RwAndHash::new(&mut buf);
            wh.write_all(&input);
            let digest = wh.finish();
            assert_eq!(digest.as_ref(), h!(&input).as_ref());
        }
        assert_eq!(buf, &input[..]);
    }
}
