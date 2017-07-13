
pub struct ReCrypt<A> {
    kem_cipher: PhantomData<A>,
    // redox_curve: PhantomData<C>,
}

impl<A: Cipher> UpEnc for ReCrypt<A> {
    // Type of the key variable
    type K = A::K;

    /* Generates a new, random key  */
    fn keygen() -> A::K {
        A::keygen()
    }

    /* Writes a re-keying token to a file for a pair of keys and a ciphertext */
    fn rekeygen(k1: A::K, k2: A::K, ct_hdr: &File, token: &File) -> Result<(), Error> {
        let tmp_filepath = get_tmp_fname("upenc-hybrid");
        let mut tmp_file = OpenOptions::new()
                            .read(true).write(true).create(true)
                            .open(&tmp_filepath).unwrap();

        let tmp_filepath2 = get_tmp_fname("upenc-hybrid");
        let mut tmp_file2 = OpenOptions::new()
                            .read(true).write(true).create(true)
                            .open(&tmp_filepath2).unwrap();

        try_or_panic!(A::decrypt(k1 ,ct_hdr, &tmp_file));
        try_or_panic!(tmp_file.seek(SeekFrom::Start(0)));
        // let k_dem1 = B::import_key(&tmp_file).unwrap();

        let mut reader = BufReader::new(tmp_file);
        let mut bytes: Vec<u8> = Vec::new();
        let key_size = redox::get_params::<C>().key_size;
        let ct_size = redox::get_params::<C>().ct_block_size;

        // recover \chi, \tau
        let (k_dem1, tag) = match reader.read_to_end(&mut bytes) {
            Ok(n) if n == (key_size + ct_size) => (BigInt::from_bytes(&bytes[..key_size]), &bytes[key_size..]),
            _ => return Err(Error::LazyError),
        };

        // generate x', y'
        let x2 = <Redox<C> as Cipher>::keygen();
        let y2 = <Redox<C> as Cipher>::keygen();

        // compute \chi'
        let mut k_dem2 = k_dem1 + x2 + y2;
        k_dem2.normalise(C::order());

        //compute \tau'
        let tag2 = &redox::update_block::<C>(x2, &tag, 0);

        try_or_panic!(<Redox<C> as Cipher>::export_key(k_dem2, &tmp_file2));
        {
            let mut writer = BufWriter::new(&tmp_file2);
            writer.write_all(tag2);
        }

        try_or_panic!(tmp_file2.seek(SeekFrom::Start(0)));
        // Hopefully writes (C_hdr || x' || y') into token file
        try_or_panic!(A::encrypt(k2, &tmp_file2, token));
        let mut writer = BufWriter::new(token);
        try_or_panic!(<Redox<C> as Cipher>::export_key(x2, &token));
        try_or_panic!(<Redox<C> as Cipher>::export_key(y2, &token));

        try_or_panic!(remove_file(tmp_filepath));
        try_or_panic!(remove_file(tmp_filepath2));

        Ok(())
        // B::rekeygen(k_dem1, k_dem2, token)
    }

    fn encrypt(k: A::K, pt: &File, ct_hdr: &File, ct_body: &File) -> Result<(), Error> {
        let tmp_filepath = get_tmp_fname("upenc-hybrid");
        let mut tmp_file = OpenOptions::new()
                            .read(true).write(true).create(true)
                            .open(&tmp_filepath).unwrap();

        let x = <Redox<C> as Cipher>::keygen();
        let y = <Redox<C> as Cipher>::keygen();
        // compute \chi
        let mut k_dem = x + y;
        k_dem.normalise(C::order());

        // compute \tau
        let mut pt_clone = try!(pt.try_clone());
        // Add prefix to this i.e. h('integrity' || m)
        let h = hash_file(&pt_clone);
        let h = &h[..redox::get_params::<C>().pt_block_size];
        let t = redox::encrypt_block::<C>(x, h, 0);
        try_or_panic!(pt_clone.seek(SeekFrom::Start(0)));


        // Write (\chi, \tau) to file
        try_or_panic!(<Redox<C> as Cipher>::export_key(k_dem, &tmp_file));
        {
            let mut writer = BufWriter::new(&tmp_file);
            writer.write_all(&t);            
        }
        try_or_panic!(tmp_file.seek(SeekFrom::Start(0)));
        // Encrypt (\chi, \tau) as ct header
        try_or_panic!(A::encrypt(k, &tmp_file, ct_hdr));
        try_or_panic!(remove_file(tmp_filepath));

        // Write block 0 as y
        try_or_panic!(<Redox<C> as Cipher>::export_key(y, ct_body));        

        // Compute the rest of the encryption
        try_or_panic!(<Redox<C> as Cipher>::encrypt(x, pt, ct_body));

        Ok(())
    }

    fn reencrypt(token: &File, ct1_hdr: &File, ct1_body: &File, ct2_hdr: &File, ct2_body: &File) -> Result<(), Error> {

        let tmp_filepath = get_tmp_fname("upenc-hybrid");
        let tmp_file = OpenOptions::new()
                            .read(true).write(true).create(true)
                            .open(&tmp_filepath).unwrap();

        let mut reader = BufReader::new(ct1_hdr);
        let mut rk_reader = BufReader::new(token);
        let mut writer = BufWriter::new(ct2_hdr);
        let mut rk_writer = BufWriter::new(&tmp_file);

        // Read size(ct1_hdr) bytes from token to ct2_hdr
        loop {
            let chunk = read_chunk(&mut reader, 128).unwrap();
            match chunk.len() {
                // EOF
                0 => break,

                // Expected block size
                n => {
                    // Read matching number of bytes from token into ct2_hdr
                    let rk_chunk = read_chunk(&mut rk_reader, n).unwrap();
                    try_or_panic!(writer.write(&rk_chunk));
                }
            }

        }

        // Read x', y'
        let key_size = redox::get_params::<C>().key_size;
        let x2 = read_chunk(&mut rk_reader, key_size).unwrap();
        let y2 = BigInt::from_bytes(&read_chunk(&mut rk_reader, key_size).unwrap());
        // Write x' into a file to be used with reencrypt
        try_or_panic!(rk_writer.write(&x2));
        try_or_panic!(rk_writer.flush());
        let mut token = open_file(&tmp_filepath);
        try_or_panic!(token.seek(SeekFrom::Start(0)));

        // read y
        let y = {
            let mut reader = BufReader::new(ct1_body);
            BigInt::from_bytes(&read_chunk(&mut reader, key_size).unwrap())
        };

        // Write y + y' into ct2_body
        let mut y_new = y + y2;
        y_new.normalise(C::order());

        <Redox<C> as Cipher>::export_key(y_new, ct2_body);


        let mut ct1_body = try_or_panic!(ct1_body.try_clone());
        // Skip the value of y
        try_or_panic!(ct1_body.seek(SeekFrom::Start(key_size as u64)));

        try_or_panic!(<Redox<C> as UpEnc>::reencrypt(&token, &ct1_body, ct2_body));
        
        Ok(())
    }
    fn decrypt(k: A::K, ct_hdr: &File, ct_body: &File, pt: &File) -> Result<(), Error> {
        let tmp_filepath = get_tmp_fname("upenc-hybrid");
        let mut tmp_file = open_file(&tmp_filepath);

        try_or_panic!(A::decrypt(k, ct_hdr, &tmp_file));
        try_or_panic!(tmp_file.seek(SeekFrom::Start(0)));

        let mut reader = BufReader::new(tmp_file);
        let mut bytes: Vec<u8> = Vec::new();
        let key_size = redox::get_params::<C>().key_size;
        let ct_size = redox::get_params::<C>().ct_block_size;

        // recover \chi, \tau
        let (k_dem, tag) = match reader.read_to_end(&mut bytes) {
            Ok(n) if n == (key_size + ct_size) => (BigInt::from_bytes(&bytes[..key_size]), &bytes[key_size..]),
            _ => return panic!(),
        };

        let y = {
            let mut reader = BufReader::new(ct_body);
            BigInt::from_bytes(&try_or_panic!(read_chunk(&mut reader, key_size)))
        };
        let mut x = k_dem - y;
        x.normalise(C::order());

        let mut pt = try!(pt.try_clone());
        let mut ct_clone = try!(ct_body.try_clone());
        try_or_panic!(ct_clone.seek(SeekFrom::Start(key_size as u64)));

        try_or_panic!(<Redox<C> as Cipher>::decrypt(x, ct_body, &pt));
        try_or_panic!(pt.seek(SeekFrom::Start(0)));

        let tag = redox::decrypt_block::<C>(x, tag, 0);
        let h = hash_file(&pt);
        if h[..tag.len()] == tag[..] {
            Ok(())
        } else {
            Err(Error::LazyError)
        }
    }

    fn import_key(key_file: &File) -> Result<A::K, Error> {
        A::import_key(key_file)
    }
    fn export_key(k: A::K, key_file: &File) -> Result<(), Error> {
        A::export_key(k, key_file)
    }
}