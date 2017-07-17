extern crate recrypt;

// use recrypt::generic::{KemDem, Naive};
use recrypt::generic::{Kss, ReCrypt};
use recrypt::RingAes;
use recrypt::KhPrf;

mod helpers;

type RegCipher = RingAes;

#[test]
fn keygen_sane() {
    helpers::keygen_sane::<Kss<RegCipher, RegCipher>>();
    helpers::keygen_sane::<ReCrypt<RegCipher, KhPrf>>();
}

#[test]
fn write_keyfile_sane() {
   helpers::write_keyfile_sane::<Kss<RegCipher, RegCipher>>();
   helpers::write_keyfile_sane::<ReCrypt<RegCipher, KhPrf>>();
}

#[test]
fn keyfile_rt() {
    helpers::keyfile_rt::<Kss<RegCipher, RegCipher>>();
    helpers::keyfile_rt::<ReCrypt<RegCipher, KhPrf>>();
}

#[test]
fn filecrypt_rt() {
    helpers::filecrypt_rt::<Kss<RegCipher, RegCipher>>(32);
    helpers::filecrypt_rt::<ReCrypt<RegCipher, KhPrf>>(31);
}

#[test]
fn encrypt_update_once() {
    helpers::encrypt_update_once::<Kss<RegCipher, RegCipher>>(32);
    helpers::encrypt_update_once::<ReCrypt<RegCipher, KhPrf>>(31);
}

#[test]
fn encrypt_update_many() {
    helpers::encrypt_update_many::<Kss<RegCipher, RegCipher>>(32);
    helpers::encrypt_update_many::<ReCrypt<RegCipher, KhPrf>>(32);
}
