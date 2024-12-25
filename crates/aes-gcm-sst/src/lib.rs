//! AES-GCM-SST per [draft-mattson-cfrg-aes-gcm-sst-13].
//!
//! [draft-mattson-cfrg-aes-gcm-sst-13]: https://www.ietf.org/archive/id/draft-mattsson-cfrg-aes-gcm-sst-01.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod tests;

pub use aead::{AeadCore, AeadInPlace, KeyInit, Nonce};
use aes::{Aes128, Aes256};
pub use cipher::{
    crypto_common::{InnerUser, KeySizeUser},
    Key,
};
use ctr::flavors;
pub use gcm_sst::Error;
use gcm_sst::{CtrGen, GcmSst, NonceSize, NONCE_SIZE};
use typenum::generic_const_mappings::U;

macro_rules! aead_impl {
    (
        $name:ident,
        $aes:ty,
        $p_max:expr,
        $tag_bits:literal,
        $aes_doc:literal,
        $tag_doc:literal $(,)?
    ) => {
        #[doc = concat!("AES-", stringify!(aes_doc), "-GCM-SST")]
        #[doc = "with"]
        #[doc = $tag_doc]
        #[doc = "authentication tag."]
        #[derive(Clone, Debug)]
        pub struct $name(AesGcmSst<$aes, U<{ $tag_bits / 8 }>>);

        impl $name {
            /// The maximum size in octets of a plaintext.
            pub const P_MAX: u64 = $p_max;
            /// The maximum size in octets of a ciphertext.
            pub const C_MAX: u64 = match Self::P_MAX.checked_add(Self::TAG_SIZE as u64) {
                Some(n) => n,
                None => unreachable!(),
            };
            /// The maximum size in octets of additional
            /// authenticated data.
            pub const A_MAX: u64 = Self::P_MAX;
            /// The size in octets of a nonce.
            pub const NONCE_SIZE: usize = NONCE_SIZE;
            /// The size in octets of a tag.
            pub const TAG_SIZE: usize = $tag_bits / 8;

            /// Creates a new instance of AES-GCM-SST.
            pub fn new(key: &Key<$aes>) -> Self {
                let cipher = <$aes>::new(key);
                let generator = CtrGen::new(cipher);
                Self(GcmSst::new(generator))
            }
        }

        impl InnerUser for $name {
            type Inner = AesGcmSst<$aes, <Self as AeadCore>::TagSize>;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &Key<$aes>) -> Self {
                Self::new(key)
            }
        }

        impl AeadCore for $name {
            type NonceSize = NonceSize;
            type TagSize = U<{ Self::TAG_SIZE }>;
            type CiphertextOverhead = Self::TagSize;
        }

        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                nonce: &Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> aead::Result<aead::Tag<Self>> {
                if u64::try_from(buffer.len()).is_ok_and(|n| n <= Self::P_MAX)
                    && u64::try_from(associated_data.len()).is_ok_and(|n| n <= Self::A_MAX)
                {
                    self.0
                        .encrypt_in_place_detached(nonce, associated_data, buffer)
                } else {
                    Err(aead::Error)
                }
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &aead::Tag<Self>,
            ) -> aead::Result<()> {
                if u64::try_from(buffer.len()).is_ok_and(|n| n <= Self::P_MAX)
                    && u64::try_from(associated_data.len()).is_ok_and(|n| n <= Self::A_MAX)
                {
                    self.0
                        .decrypt_in_place_detached(nonce, associated_data, buffer, tag)
                } else {
                    Err(aead::Error)
                }
            }
        }
    };
}
pub(crate) use aead_impl;

aead_impl!(
    AesGcm128Sst4,
    Aes128,
    (1 << 36) - 48,
    32,
    "128",
    "a four octet (32 bit)"
);
aead_impl!(
    AesGcm128Sst8,
    Aes128,
    (1 << 36) - 48,
    64,
    "128",
    "an eight octet (64 bit)"
);
aead_impl!(
    AesGcm128Sst12,
    Aes128,
    1 << 35,
    96,
    "128",
    "a twelve octet (96 bit)"
);
aead_impl!(
    AesGcm128Sst14,
    Aes128,
    1 << 19,
    112,
    "128",
    "a fourteen octet (112 bit)"
);

aead_impl!(
    AesGcm256Sst4,
    Aes256,
    (1 << 36) - 48,
    32,
    "256",
    "a four octet (32 bit)"
);
aead_impl!(
    AesGcm256Sst8,
    Aes256,
    (1 << 36) - 48,
    64,
    "256",
    "an eight octet (64 bit)"
);
aead_impl!(
    AesGcm256Sst12,
    Aes256,
    1 << 35,
    96,
    "256",
    "a twelve octet (96 bit)"
);
aead_impl!(
    AesGcm256Sst14,
    Aes256,
    1 << 19,
    112,
    "256",
    "a fourteen octet (112 bit)"
);

type Ctr32BE<A> = CtrGen<A, flavors::Ctr32BE>;
type AesGcmSst<A, T> = GcmSst<Ctr32BE<A>, T>;
