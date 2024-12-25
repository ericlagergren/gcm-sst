#![cfg(test)]

use serde::Deserialize;

use crate::{AeadInPlace, AesGcm128Sst4, KeyInit, Nonce};

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
    let nonce = Nonce::<AesGcm128Sst4>::from_slice(&tests.nonce);
    for test in tests.cases {
        let aead = AesGcm128Sst4::new_from_slice(&tests.key).unwrap();

        let mut got_ct = test.plaintext.clone();
        let got_tag = aead
            .encrypt_in_place_detached(&nonce, &test.aad, &mut got_ct)
            .expect("should be able to encrypt");
        assert_eq!(&got_tag[..], &test.tag[..], "case #{}", test.name);
        assert_eq!(&got_ct, &test.ciphertext, "case #{}", test.name);

        let mut got_pt = got_ct.clone();
        aead.decrypt_in_place_detached(&nonce, &test.aad, &mut got_pt, &got_tag)
            .expect("should be able to decrypt");
        assert_eq!(&got_pt, &test.plaintext, "case #{}", test.name);
    }
}
