#![cfg(test)]

use aes::{Aes128, Aes256};
use serde::Deserialize;
use typenum::{U10, U4, U8};

use crate::{GcmSst, Key, Nonce, Tag};

type AesGcm128Sst4 = GcmSst<Aes128, U4>;
// type AesGcm128Sst8 = GcmSst<Aes128, U8>;
// type AesGcm128Sst10 = GcmSst<Aes128, U10>;
// type AesGcm256Sst4 = GcmSst<Aes256, U4>;
// type AesGcm256Sst8 = GcmSst<Aes256, U8>;
// type AesGcm256Sst10 = GcmSst<Aes256, U10>;

#[derive(Deserialize)]
struct TestCases {
    #[serde(with = "hex::serde")]
    key: Vec<u8>,
    #[serde(with = "hex::serde")]
    nonce: Vec<u8>,
    cases: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
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

#[test]
fn test_aes_gcm_128_vectors() {
    const DATA: &str = include_str!("testdata/aes_gcm_128_sst.json");

    let tests: TestCases = serde_json::from_str(DATA).expect("should be able to parse test cases");
    let key = Key::<Aes128>::from_slice(&tests.key);
    let nonce = Nonce::from_slice(&tests.nonce);
    for test in tests.cases {
        let mut got_ct = vec![0u8; test.ciphertext.len()];

        let aead = AesGcm128Sst4::new(&key);
        let got_tag = aead
            .seal(&mut got_ct, &nonce, &test.plaintext, &test.aad)
            .expect("should be able to encrypt");
        assert_eq!(&got_tag[..], &test.tag[..], "case #{}", test.name);
        assert_eq!(&got_ct, &test.ciphertext, "case #{}", test.name);

        let mut got_pt = vec![0u8; test.plaintext.len()];
        aead.open(&mut got_pt, &nonce, &test.ciphertext, &got_tag, &test.aad)
            .expect("should be able to decrypt");
        assert_eq!(&got_pt, &test.plaintext, "case #{}", test.name);
    }
}
