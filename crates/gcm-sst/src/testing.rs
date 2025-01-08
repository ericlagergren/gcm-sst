//! Testing utilities.

#![cfg(feature = "testing")]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]

use std::sync::LazyLock;

use aead::AeadInPlace;
use cipher::KeyInit;
use serde::Deserialize;

use crate::{Nonce, NonceSize};

/// Test cases.
#[derive(Deserialize)]
pub struct TestCases {
    #[serde(with = "hex::serde")]
    key: Vec<u8>,
    #[serde(with = "hex::serde")]
    nonce: Vec<u8>,
    cases: Vec<TestCase>,
}

/// A specific test case.
#[derive(Deserialize)]
pub struct TestCase {
    name: String,
    #[serde(with = "hex::serde")]
    aad: Vec<u8>,
    #[serde(with = "hex::serde")]
    plaintext: Vec<u8>,
    #[serde(with = "hex::serde")]
    tag: Vec<u8>,
    #[serde(with = "hex::serde")]
    ciphertext: Vec<u8>,
}

/// Performs the test cases.
pub fn run_tests<A>(tests: &TestCases)
where
    A: KeyInit + AeadInPlace<NonceSize = NonceSize>,
{
    let nonce = Nonce::from_slice(&tests.nonce);
    for test in tests.cases.iter() {
        let aead = A::new_from_slice(&tests.key).unwrap();

        let mut got_ct = test.plaintext.clone();
        let got_tag = aead
            .encrypt_in_place_detached(nonce, &test.aad, &mut got_ct)
            .expect("should be able to encrypt");
        assert_eq!(&got_tag[..], &test.tag[..], "#{}", test.name);
        assert_eq!(&got_ct, &test.ciphertext, "#{}", test.name);

        let mut got_pt = got_ct.clone();
        aead.decrypt_in_place_detached(nonce, &test.aad, &mut got_pt, &got_tag)
            .expect("should be able to decrypt");
        assert_eq!(&got_pt, &test.plaintext, "#{}", test.name);
    }
}

macro_rules! export {
    ($name:ident, $path:literal) => {
        #[doc = "Test data for "]
        #[doc = stringify!($name)]
        pub static $name: LazyLock<TestCases> = LazyLock::new(|| {
            let data = include_str!(concat!("testdata/", $path, ".json"));
            serde_json::from_str(data).expect("should be able to deserialize")
        });
    };
}
export!(AES_128_GCM_SST4, "aes_128_gcm_sst4");
export!(AES_128_GCM_SST8, "aes_128_gcm_sst8");
export!(AES_256_GCM_SST8, "aes_256_gcm_sst8");
