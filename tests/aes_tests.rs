extern crate recrypt;

use recrypt::generic::Naive;
use recrypt::RingAes;

mod helpers;

#[test]
fn encrypt_sane() {
    helpers::filecrypt_rt::<Naive<RingAes>>(16);
}

