#![cfg(test)]

use aes::Aes128;
use cipher::{KeyInit, KeyIvInit};
use ctr::flavors;
use serde::Deserialize;
use typenum::U4;

use crate::{rust_crypto::CtrGen, GcmSst, Nonce};

//type Ctr32BE<A> = CtrCore<A, ctr::flavors::Ctr32BE>;

type Ctr32BE<A> = CtrGen<A, flavors::Ctr32BE>;
type Aes128Ctr32BE = Ctr32BE<Aes128>;
type AesGcm128Sst4 = GcmSst<Aes128Ctr32BE, U4>;

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
    let key = Aes128Ctr32BE::new_from_slices(&tests.key);
    let nonce = Nonce::from_slice(&tests.nonce);
    for test in tests.cases {
        let mut got_ct = vec![0u8; test.ciphertext.len()];

        let aead = AesGcm128Sst4::new(Aes128::new(&key));
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
