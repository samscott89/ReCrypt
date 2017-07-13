//! Methods to profile schemes

extern crate rand;
extern crate time;

use super::*;
use generic::*;
use io::*;

use std::fs::{metadata,remove_dir_all,create_dir,File};
use std::io::{Write,BufWriter};
use std::path::{Path,PathBuf};
use std::env;

// type ProfileCipher = Kss<RingAes, RingAes>;
type ProfileCipher = ReCrypt<RingAes, KhPrf>;

pub fn run_all() {
    profile_init();

    println!("{:20} {:>15}   {:>18}   {:>18}   {:>15}",
        "Profile", "Average Time", "Min Time", "Max Time", "Iterations");

    let params = vec![(1000,1), (100,1024), (100,1024*1024), (1, 1024*1024*1024)];
    println!("\nReCrypt<RingAes, KhPrf>");
    for (iterations,size) in params {
        profile_init();
        profile_upenc::<ProfileCipher>(iterations, size);
        profile_clean();
    }
}


// Run and time a closure and print the results.
// NOTE: This is not quite right, ideally we should run setup code each time
//       to allow parameters to differ.
fn run_profile<F, R, G, Args, InArgs: Copy>(name: &str, iterations: usize, 
    setup_args: InArgs, setup: &G, closure: F) 
        where F: FnMut(Args) -> R, G: Fn(InArgs) -> Args {
    let (avg_time,min_time,max_time) = profile_code(iterations, setup_args, 
        setup, closure);
    println!("{:20} {:>15} ns   {:>15} ns   {:>15} ns     {:>10}", 
        name, fmt_val(avg_time), fmt_val(min_time), fmt_val(max_time), 
        iterations);
}

// Run and time a closure and print the results.
fn profile_code<F, R, G, Args, InArgs: Copy>(iterations: usize, 
    setup_args: InArgs, setup: &G, mut closure: F) -> (u64,u64,u64)
        where F: FnMut(Args) -> R, G: Fn(InArgs) -> Args {
    let mut accum_time = 0;
    let mut min_time = u64::max_value();
    let mut max_time = 0;
    for _ in 0..iterations { 
        let input = setup(setup_args);
        let start = time::precise_time_ns();
        closure(input);
        let end = time::precise_time_ns();
        let time = end - start;
        if time > max_time {
            max_time = time;
        }
        if time < min_time {
            min_time = time;
        }
        accum_time += time;
    }
    let avg_time = accum_time/iterations as u64;
    (avg_time,min_time,max_time)
}

fn profile_upenc<Scheme: UpEnc>(iterations:usize, bytes:usize) {
    let prep_pt = &|l|{
        let k = Scheme::keygen();
        let m = random_vec(l);
        let pt_path = get_tmp_fname("upenc-profile");
        create_test_file(&pt_path, &m);
        (k, pt_path)
    };
    let enc = &|(k, pt_path)|{
        let ct_path = get_tmp_fname("upenc-profile");
        let mut pt_file = open_file(&pt_path);
        let mut ct_h = File::create(extend_path(&ct_path, "_h")).unwrap();
        let mut ct_b = File::create(extend_path(&ct_path, "_b")).unwrap();
        Scheme::encrypt(k, &mut pt_file, &mut ct_h, &mut ct_b).unwrap();
        ct_path
    };
    let prep_ct = &|l|{
        let (k, pt_path) = prep_pt(l);
        let ct_path = enc((k.clone(), pt_path));
        (k, ct_path)
    };
    let rekeygen = &|(k1, ct_path)|{
        let k2 = Scheme::keygen();
        let token_path = get_tmp_fname("upenc-profile");
        let mut ct_h = File::open(extend_path(&ct_path, "_h")).unwrap();
        let mut token_file = open_file(&token_path);
        Scheme::rekeygen(k1, k2.clone(), &mut ct_h, &mut token_file).unwrap();
        (k2, token_path)
    };
    let prep_up_ct = &|l|{
        let (k, ct_path) = prep_ct(l);
        let (k2, token_path) = rekeygen((k, ct_path.clone()));
        (k2, token_path, ct_path)
    };
    let reenc = &|(_, token_path, ct_path)|{
        let ct2_path = get_tmp_fname("upenc-profile");
        let mut token_file = open_file(&token_path);
        let mut ct1_h = File::open(extend_path(&ct_path, "_h")).unwrap();
        let mut ct1_b = File::open(extend_path(&ct_path, "_b")).unwrap();

        let mut ct2_h = File::create(extend_path(&ct2_path, "_h")).unwrap();
        let mut ct2_b = File::create(extend_path(&ct2_path, "_b")).unwrap();
        Scheme::reencrypt(&mut token_file, &mut ct1_h, &mut ct1_b, &mut ct2_h, &mut ct2_b).unwrap();
        ct2_path
    };
    let prep_final_ct = &|l|{
        let (k2, token_path, ct_path) = prep_up_ct(l);
        let ct2_path = reenc((k2.clone(), token_path, ct_path.clone()));
        (k2, ct2_path)
    };
    let dec = &|(k, ct_path)|{
        let pt = get_tmp_fname("upenc-profile");
        let mut pt_file = open_file(&pt);

        let mut ct_h = File::open(extend_path(&ct_path, "_h")).unwrap();
        let mut ct_b = File::open(extend_path(&ct_path, "_b")).unwrap();
        Scheme::decrypt(k, &mut ct_h, &mut ct_b, &mut pt_file).unwrap()
    };

    run_profile("KeyGen", iterations, (),&|()|{
    }, |()|{
        Scheme::keygen()
    });
    let enc_text = format!("Enc        {}", get_display_size(bytes));
    let rkg_text = format!("ReKeyGen   {}", get_display_size(bytes));
    let re_text  = format!("ReEnc      {}", get_display_size(bytes));
    let dec_text = format!("Decrypt    {}", get_display_size(bytes));
    run_profile(&enc_text, iterations, bytes, prep_pt, enc);
    run_profile(&rkg_text, iterations, bytes, prep_ct, rekeygen);
    run_profile(&re_text,  iterations, bytes, prep_up_ct, reenc);
    run_profile(&dec_text, iterations, bytes, prep_final_ct, dec);
}

// Converts byte count into a human-readable strings. Examples:
// 100 B
// 50 KB
// 13.3 MB
fn get_display_size(n:usize) -> String {
    let kb = 1024;
    let mb = 1024*kb;
    let gb = 1024*mb;
    let (factor,appendix) = 
        match n {
            x if x >= gb => (gb,"GB"),
            x if x >= mb => (mb,"MB"),
            x if x >= kb => (kb,"KB"),
            _ => (1,"B")
        };
    format!("{} {}", (n as f32)/(factor as f32), appendix)
}


// Writes the specified contents to a file.
fn create_test_file(fname: &Path, contents: &[u8]) {
    let f = open_file(fname);
    let mut writer = BufWriter::new(f);
    writer.write_all(contents).unwrap();
}

fn fmt_val(x: u64) -> String {
    let mut output: String = String::new();
    let mut y = x;
    while y/1000 > 0 {
        output = format!(",{:0>3}{}", y%1000,output);
        y = y/1000;
    }
    format!("{}{}", y%1000, output)
}

fn extend_path(p: &PathBuf, ext: &str) -> PathBuf {
    PathBuf::from(String::from(p.as_path().to_str().unwrap()) + ext)
}

fn profile_init(){
    let test_dir = env::temp_dir().join("upenc-profile");
    remove_dir_all(&test_dir).unwrap_or(());
    create_dir(&test_dir).unwrap();
}

fn profile_clean(){
    let test_dir = env::temp_dir().join("upenc-profile");
    remove_dir_all(&test_dir).unwrap_or(());   
}

pub fn get_tmp_fname(prefix: &str) -> PathBuf {
    let mut tmp_path = env::temp_dir();
    tmp_path.push(prefix);
    if !metadata(&tmp_path).is_ok(){
        create_dir(&tmp_path).expect(&format!("could not create tmp directory: {:?}", tmp_path));
    }
    let r = rand::random::<u64>();
    tmp_path.join(format!("{}", r))
}

pub fn random_vec(n: usize) -> Vec<u8> {
    let mut v = Vec::new();
    for _ in 0..n {
        v.push(rand::random::<u8>());
    }
    v
}
