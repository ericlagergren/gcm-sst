#![cfg(test)]

use gcm_sst::testing::{run_tests, AES_128_GCM_SST4, AES_128_GCM_SST8, AES_256_GCM_SST8};

use crate::{Aes128GcmSst4, Aes128GcmSst8, Aes256GcmSst8};

macro_rules! tests {
    ($name:ident, $aead:ident, $tests:ident) => {
        #[test]
        fn $name() {
            run_tests::<$aead>(&*$tests);
        }
    };
}
tests!(aes_gcm_128_sst4, Aes128GcmSst4, AES_128_GCM_SST4);
tests!(aes_gcm_128_sst8, Aes128GcmSst8, AES_128_GCM_SST8);
tests!(aes_gcm_256_sst8, Aes256GcmSst8, AES_256_GCM_SST8);
