//! AES-GCM-SST per [draft-mattson-cfrg-aes-gcm-sst-01].
//!
//! <https://www.ietf.org/archive/id/draft-mattsson-cfrg-aes-gcm-sst-01.html>

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod tests;

use aead::{AeadCore, AeadInPlace};
use aes::{Aes128, Aes256};
pub use cipher::Key;
pub use gcm_sst::Error;
use gcm_sst::{ArrayLength, GcmSst, NonceSize};
use subtle::ConstantTimeEq;
use typenum::{U10, U4, U8};

macro_rules! aead_impl {
    ($name:ident, $aes:ty, $tag:ty, $bits) => {
        #[doc(concat!(
            stringify!(aes_bits), "-bit AES-GCM-SST with ",
            stringify!(tag_bits), "authentication tag.",
        ))]
        pub struct $name(AesGcmSst<$aes, $tag>);

        impl $name {
            /// The maximum size in octets of a plaintext.
            pub const P_MAX: u64 = (1 << 36) - 48;
            /// The maximum size in octets of a ciphertext.
            pub const C_MAX: u64 = Self::P_MAX + Self::TAG_SIZE as u64;
            /// The maximum size in octets of the additional data.
            pub const A_MAX: u64 = 1 << 36;
            /// The size in octets of a nonce.
            pub const NONCE_SIZE: usize = NONCE_SIZE;;
            /// The size in octets of a tag.
            pub const TAG_SIZE: usize = $tag::USIZE;

            /// Creates a new instance of AES-GCM-SST.
            pub fn new(key: &Key<$aes>) -> Self {
                let cipher = <$aes>::new(key);
                Self(GcmSst::new(cipher))
            }
        }

        impl KeySizeUser for $name {
            type KeySize = $aes::KeySize;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &Key<$aes>) -> Self {
                Self::new(key)
            }
        }

        impl AeadCore for $name {
            type NonceSize = NonceSize;
            type TagSize = $tag;
            type CiphertextOerhead = $tag;
        }

        impl AeadInPlace for $name {
            fn encrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8]
            ) -> aead::Result<aead::Tag<Self>> {
                if buffer.len() as u64 > Self::P_MAX ||
                    associated_data.len() as u64 > Self::A_MAX {
                    return Err(Error);
                }
                self.0.seal(nonce, plaintext)
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8]
                tag: &aead::Tag<Self>,
            ) -> aead::Result<()> {
                if buffer.len() as u64 > Self::P_MAX ||
                    associated_data.len() as u64 > Self::A_MAX {
                    return Err(Error);
                }
            }
        }
    };
}
pub(crate) use aead_impl;

aead_impl!(AesGcm128Sst4, Aes128, U4, "128", "a four octet (32 bit)");
aead_impl!(AesGcm128Sst8, Aes128, U8, "128", "an eight octet (64 bit)");
aead_impl!(AesGcm128Sst10, Aes128, U10, "128", "a ten octet (80 bit)");

aead_impl!(AesGcm256Sst4, Aes256, U4, "256", "a four octet (32 bit)");
aead_impl!(AesGcm256Sst8, Aes256, U8, "256", "an eight octet (64 bit)");
aead_impl!(AesGcm256Sst10, Aes256, U10, "256", "a ten octet (80 bit)");

type AesGcmSst<A, T> = GcmSst<CtrBE32<A>, T>;
