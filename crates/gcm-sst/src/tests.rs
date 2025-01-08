#![cfg(test)]

use aes::{Aes128, Aes256};
use ctr::flavors::Ctr32BE;
use typenum::{U4, U8};

use crate::{
    rust_crypto::CtrGen,
    testing::{run_tests, AES_128_GCM_SST4, AES_128_GCM_SST8, AES_256_GCM_SST8},
    GcmSst,
};

type Aes128GcmSst4 = GcmSst<CtrGen<Aes128, Ctr32BE>, U4>;
type Aes128GcmSst8 = GcmSst<CtrGen<Aes128, Ctr32BE>, U8>;
type Aes256GcmSst8 = GcmSst<CtrGen<Aes256, Ctr32BE>, U8>;

macro_rules! tests {
    ($name:ident, $aead:ty, $tests:ident) => {
        #[test]
        fn $name() {
            run_tests::<$aead>(&*$tests);
        }
    };
}
tests!(aes_gcm_128_sst4, Aes128GcmSst4, AES_128_GCM_SST4);
tests!(aes_gcm_128_sst8, Aes128GcmSst8, AES_128_GCM_SST8);
tests!(aes_gcm_256_sst8, Aes256GcmSst8, AES_256_GCM_SST8);
