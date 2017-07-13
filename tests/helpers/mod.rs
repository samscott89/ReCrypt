extern crate rand;

use recrypt::*;

use std::env;
use std::fs::{metadata, remove_dir_all,create_dir,File, OpenOptions};
use std::path::{Path,PathBuf};
use std::io::{Write,BufWriter};
use std::collections::HashSet;

use std::sync::{Once, ONCE_INIT};

static TEST_SETUP: Once = ONCE_INIT;

pub const TEST_REPEAT : u64 = 100;

// "Debug print": prints var_name=value on a single line.
#[macro_export]
macro_rules! dprint {
    ($a:expr) => (println!("{:?}={:?}", stringify!($a),$a))
}

#[macro_export]
macro_rules! testrepeat {
    ($a:block) => (for _ in 0..TEST_REPEAT { $a })
}

pub fn test_setup(){
    TEST_SETUP.call_once(|| {
        let test_dir = env::temp_dir().join("upenc");
        remove_dir_all(&test_dir).unwrap_or(());
        create_dir(&test_dir).unwrap();
    });
}

// Generates a new tmp file and populates it with random bytes.
pub fn new_random_file(n: usize) -> PathBuf {
    let fname = get_tmp_fname("upenc");
    create_test_file(&fname, &random_vec(n));
    fname
}

// Gets a random filename in the path /tmp.
pub fn get_tmp_fname(prefix: &str) -> PathBuf {
    let mut tmp_path = env::temp_dir();
    tmp_path.push(prefix);
    if !metadata(&tmp_path).is_ok(){
        create_dir(&tmp_path).expect(&format!("could not create tmp directory: {:?}", tmp_path));
    }
    let r = rand::random::<u64>();
    tmp_path.join(format!("{}", r))
}

pub fn open_file<P: AsRef<Path>>(path: P) -> File {
    OpenOptions::new().read(true).write(true).create(true).open(path).unwrap()
}

// TODO: This is redundant to common::random_vec()
// Generates a vector of random u8 values of the specified length.
pub fn random_vec(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(rand::random::<u8>());
    }
    v
}


// Runs: `diff f1 f2` and reports the result.
pub fn diff_files(f1: &Path, f2: &Path) -> bool {
    use std::process::Command;
    let output = Command::new("diff").arg(f1).arg(f2)
        .output().unwrap();
    match output.status.code() {
        Some(0) => true,
        _ => false
    }
}

// Writes the specified contents to a file.
pub fn create_test_file(fname: &Path, contents: &[u8]) {
    let f = open_file(fname);
    let mut writer = BufWriter::new(f);
    writer.write_all(contents).unwrap();
}

// Runs a file operation (encrypt, decrypt, update) on the 
// in path. Returns the path of the newly created file that holds
// the result.
pub fn transform_file<Scheme: UpEnc>(k1: Scheme::K, k2: Option<Scheme::K>, inpath: &PathBuf, operation: &str) -> PathBuf {
    let outpath = get_tmp_fname("upenc");

    match operation {
        "encrypt" => {
            // Plaintext file is inpath
            let mut pt_file = open_file(inpath);

            // Ciphertext path is split into two:
            // ${outpath}_hdr, ${outpath}_body
            let ct_hdr_path = extend_path(&outpath, "_hdr");
            let ct_path = extend_path(&outpath, "_body");
            // print!("ct header: {:?} ct path: {:?}", ct_hdr_path, ct_path);
            let mut ct_hdr = open_file(&ct_hdr_path);
            let mut ct_body = open_file(&ct_path);

            Scheme::encrypt(k1, &mut pt_file, &mut ct_hdr, &mut ct_body).unwrap()

        },
        "decrypt" => {
            let mut pt_file = open_file(&outpath);

            let ct_hdr_path = extend_path(inpath, "_hdr");
            let ct_path = extend_path(inpath, "_body");

            let mut ct_hdr = open_file(&ct_hdr_path);
            let mut ct_body = open_file(&ct_path);

            let res = Scheme::decrypt(k1, &mut ct_hdr, &mut ct_body, &mut pt_file);
            if res.is_err() {
                println!("{:?}", res);
            }
        },
        "rekeygen" => {
            let rk_path = extend_path(inpath, "_rk");
            let ct_hdr_path = extend_path(inpath, "_hdr");

            let mut rkfile = open_file(&rk_path);
            let mut ctfile = open_file(&ct_hdr_path);

            Scheme::rekeygen(k1, k2.unwrap(), &mut ctfile, &mut rkfile).unwrap();
        }
        "reencrypt" => {
            // Input ciphertext files
            let ct_hdr_path = extend_path(inpath, "_hdr");
            let ct_path = extend_path(inpath, "_body");
            let rk_path = extend_path(inpath, "_rk");

            let mut rk_file = open_file(&rk_path);
            let mut ct_hdr = open_file(&ct_hdr_path);
            let mut ct_body = open_file(&ct_path);

            // Output ciphertext files
            let new_ct_hdr_path = extend_path(&outpath, "_hdr");
            let new_ct_path = extend_path(&outpath, "_body");

            let mut ct_hdr2 = open_file(&new_ct_hdr_path);
            let mut ct_body2 = open_file(&new_ct_path);
            
            Scheme::reencrypt(&mut rk_file, &mut ct_hdr, &mut ct_body, &mut ct_hdr2, &mut ct_body2).unwrap();
        }
        _ => panic!("Unknown operation: {}", operation)
    };
    outpath
}

// Runs create-encrypt-decrypt-diff on the given plaintext bytes
// using a random key.
pub fn encrypt_file_rt<Scheme: UpEnc>(pt_bytes: &[u8]) {
    // Run encrypt RT by skipping any updates.
    enc_upd_rt::<Scheme>(pt_bytes, 0);
    enc_upd_rt_buffer::<Scheme>(pt_bytes, 0);
}

// Runs create-encrypt-update-decrypt-diff on the given plaintext bytes
// using a random keys.
pub fn enc_upd_rt<Scheme: UpEnc>(pt_bytes: &[u8], update_cnt: u16) {
    test_setup();
    let key = Scheme::keygen();

    // Write the input file
    let pt_path = get_tmp_fname("upenc");
    create_test_file(&pt_path, pt_bytes);

    // Encrypt
    let ct_path = transform_file::<Scheme>(key.clone(), None, &pt_path, "encrypt");
    assert!(!diff_files(&pt_path, &ct_path));

    // Update
    let mut cur_ct_path = ct_path;
    let mut cur_key = key;
    for _ in 0..update_cnt {
        let newkey = Scheme::keygen();
        transform_file::<Scheme>(cur_key, Some(newkey.clone()), &cur_ct_path, "rekeygen");
        cur_ct_path = transform_file::<Scheme>(newkey.clone(), None, &cur_ct_path, "reencrypt");
        cur_key = newkey;
    }

    // Decrypt
    let rec_path = transform_file::<Scheme>(cur_key, None, &cur_ct_path, "decrypt");

    // Useful for debugging.
    println!("Plaintext file: {}", &pt_path.display());
    println!("Ciphertext file: {}", &cur_ct_path.display());
    println!("Recovered file: {}", &rec_path.display());

    // Verify the result.
    assert!(diff_files(&pt_path, &rec_path));
}

// Runs create-encrypt-update-decrypt-diff on the given plaintext bytes
// using a random keys.
pub fn enc_upd_rt_buffer<Scheme: UpEnc>(pt_bytes: &[u8], update_cnt: u16) {
    test_setup();
    let key = Scheme::keygen();

    // // Write the input file
    // let pt_path = get_tmp_fname("upenc");
    // create_test_file(&pt_path, pt_bytes);

    // Encrypt
    let mut ct_hdr = Vec::new();
    let mut ct_body= Vec::new();
    Scheme::encrypt(key.clone(), &mut (&pt_bytes[..]), &mut ct_hdr, &mut ct_body).unwrap();
    // println!("({:?}, {:?})", ct_hdr, ct_body);
    assert!(ct_body != pt_bytes);

    // Update
    let mut cur_key = key;
    for _ in 0..update_cnt {
        let newkey = Scheme::keygen();
        let mut upd_hdr = Vec::new();
        let mut upd_body = Vec::new();
        let mut rk_buf = Vec::new();
        Scheme::rekeygen(cur_key, newkey.clone(), &mut (&ct_hdr[..]), &mut rk_buf).unwrap();
        Scheme::reencrypt(&mut (&rk_buf[..]), &mut (&ct_hdr[..]), &mut (&ct_body[..]), &mut upd_hdr, &mut upd_body).unwrap();
        ct_hdr = upd_hdr;
        ct_body = upd_body;
        // transform_file::<Scheme>(cur_key, Some(newkey.clone()), &cur_ct_path, "rekeygen");
        // cur_ct_path = transform_file::<Scheme>(newkey.clone(), None, &cur_ct_path, "reencrypt");
        cur_key = newkey;
    }

    // Decrypt
    let mut pt_buf = Vec::new();
    Scheme::decrypt(cur_key, &mut (&ct_hdr[..]), &mut (&ct_body[..]), &mut pt_buf).unwrap();
    // let rec_path = transform_file::<Scheme>(cur_key, None, &cur_ct_path, "decrypt");

    assert_eq!(pt_bytes, &pt_buf[..]);
}

// Retrieves some delightful plaintext test cases.
pub fn get_plaintexts(block_size: usize) -> Vec<Vec<u8>> {
    let mut result = Vec::new();
    result.push(String::from("Something legible").into_bytes());
    result.push(vec![131u8; 5]);
    result.push(vec![0u8; block_size]);
    result.push(vec![0u8; block_size+1]);
    result.push(vec![255u8; block_size]);
    result.push(vec![255u8; block_size+1]);
    // result.push(random_vec(block_size));
    // result.push(random_vec(block_size+1));
    // result.push(random_vec(block_size*5));
    // result.push(random_vec(block_size*5+100));
    // result.push(random_vec(block_size*10-1));
    // result.push(random_vec(block_size*300));
    result
}

// Tests read/write k to/from a keyfile.
pub fn read_write_key<Scheme: UpEnc>(k: Scheme::K) { 
    let kfile = get_tmp_fname("upenc");
    let mut ofile = open_file(&kfile);
    k.write_key( &mut ofile).unwrap();
    let mut ifile = open_file(&kfile);
    let _k = Scheme::K::read_key(&mut ifile).unwrap();
    assert_eq!(k, _k);
}

fn extend_path(p: &PathBuf, ext: &str) -> PathBuf {
    PathBuf::from(String::from(p.as_path().to_str().unwrap()) + ext)
}


pub fn keygen_sane<Scheme: UpEnc>() {
    test_setup();
    testrepeat!({
        Scheme::keygen();
        // assert_eq!(k.val.sign, relic::bn::BN_POSITIVE);
    });
}

 pub fn rekeygen_sane<Scheme: UpEncCtxtIndep>() {
    test_setup();
    testrepeat!({
        let k1 = Scheme::keygen();
        let k2 = Scheme::keygen();
        let mut rkfile = open_file(&get_tmp_fname("upenc"));
        Scheme::rekeygen(k1, k2, &mut rkfile).unwrap();
    });
}

pub fn write_keyfile_sane<Scheme: UpEnc>() {
    test_setup();
    let kfile = get_tmp_fname("upenc");
    let mut f = open_file(&kfile);
    Scheme::keygen().write_key(&mut f).unwrap();
}


pub fn keyfile_rt<Scheme: UpEnc>() {
    test_setup();
    for _ in 0..10 {
        let k = Scheme::keygen();
        read_write_key::<Scheme>(k);
    }
}

pub fn update_tokenfile_sane<Scheme: UpEncCtxtIndep>() {
    // Make an initial keyfile.
    test_setup();
    let kfname = get_tmp_fname("upenc");
    let mut kfile = open_file(&kfname);
    Scheme::keygen().write_key( &mut kfile).unwrap();

    // Re-open the keyfile.
    kfile = open_file(&kfname);

    // Create files for the new keyfile and token file.
    let mut tokenfile = File::create(&get_tmp_fname("upenc")).unwrap();
    let k1 = Scheme::K::read_key(&mut kfile).unwrap();
    let k2 = Scheme::keygen();
    // Create an update tokenfile.
    Scheme::rekeygen(k1, k2, &mut tokenfile).unwrap();
 }

pub fn encrypt_file_sane<Scheme: UpEncCtxtIndep>() {
    test_setup();
    let key = Scheme::keygen();
    let bytes = [130u8; 100];

    let ptfile = get_tmp_fname("upenc");
    let ctfile = get_tmp_fname("upenc");

    create_test_file(&ptfile, &bytes);
    let mut infile = open_file(&ptfile);
    let mut outfile = open_file(&ctfile);
    Scheme::encrypt(key, &mut infile, &mut outfile).unwrap();
}

pub fn filecrypt_rt<Scheme: UpEnc>(block_size: usize) {
    for pt in get_plaintexts(block_size) {
        encrypt_file_rt::<Scheme>(&pt[..]);
    }
}

// Run tests with a single update function.
pub fn encrypt_update_once<Scheme: UpEnc>(block_size: usize) {
    for pt in get_plaintexts(block_size) {
        enc_upd_rt::<Scheme>(&pt[..], 1);
        enc_upd_rt_buffer::<Scheme>(&pt[..], 1);
    }
}

// Tests with multiple file updates.
pub fn encrypt_update_many<Scheme: UpEnc>(block_size: usize) {
    let updates = 5;
    for pt in get_plaintexts(block_size) {
        enc_upd_rt::<Scheme>(&pt[..], updates);
        enc_upd_rt_buffer::<Scheme>(&pt[..], updates);
    }
}


