extern crate recrypt;

use recrypt::generic::{KemDem, Naive};
use recrypt::{KhPrf, RingAes};

mod helpers;

type TestCipher = RingAes;

#[test]
fn sanity() {
    helpers::test_setup();
}

#[test]
fn keygen_sane() {
    helpers::keygen_sane::<Naive<TestCipher>>();
    helpers::keygen_sane::<KemDem<TestCipher>>();
}

#[test]
fn write_keyfile_sane() {
   helpers::write_keyfile_sane::<Naive<TestCipher>>();
   helpers::write_keyfile_sane::<KemDem<TestCipher>>();  
}

#[test]
fn keyfile_rt() {
    helpers::keyfile_rt::<Naive<TestCipher>>();
    helpers::keyfile_rt::<KemDem<TestCipher>>();
}

#[test]
fn filecrypt_rt() {
    helpers::filecrypt_rt::<Naive<TestCipher>>(32);
    helpers::filecrypt_rt::<KemDem<TestCipher>>(32);
}

#[test]
fn encrypt_update_once() {
    helpers::encrypt_update_once::<Naive<TestCipher>>(32);
    helpers::encrypt_update_once::<KemDem<TestCipher>>(32);
}

#[test]
fn encrypt_update_many() {
    helpers::encrypt_update_many::<Naive<TestCipher>>(32);
    helpers::encrypt_update_many::<KemDem<TestCipher>>(32);
}
