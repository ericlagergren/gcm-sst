//! AES-GCM-SST per [draft-mattson-cfrg-aes-gcm-sst-13].
//!
//! [draft-mattson-cfrg-aes-gcm-sst-13]: https://www.ietf.org/archive/id/draft-mattsson-cfrg-aes-gcm-sst-01.html

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(feature = "std", test)), no_std)]

mod tests;

pub use aead;
use aead::{AeadCore, AeadInPlace, Key, KeyInit};
use aes::{Aes128, Aes256};
use cipher::crypto_common::InnerUser;
use ctr::flavors::Ctr32BE;
use gcm_sst::{rust_crypto::CtrGen, GcmSst};
pub use gcm_sst::{
    rust_crypto::NonceSize, Error, Nonce, Tag, MAX_TAG_SIZE, MIN_TAG_SIZE, NONCE_SIZE,
};

type AesGcmSst<A, const T: usize> = GcmSst<CtrGen<A, Ctr32BE>, T>;

macro_rules! aead_impl {
    (
        $name:ident,
        $aes:ty,
        $p_max:expr,
        $tag_bits:literal,
        $aes_bits:literal,
        $tag_octets:literal $(,)?
    ) => {
        #[doc = concat!("AES-", stringify!($aes_bits), "-GCM-SST")]
        #[doc = "with"]
        #[doc = $tag_octets]
        #[doc = " octet"]
        #[doc = concat!("(", stringify!($tag_bits))]
        #[doc = "bit) authentication tag."]
        #[derive(Clone, Debug)]
        pub struct $name(AesGcmSst<$aes, { $tag_bits / 8 }>);

        impl $name {
            /// The maximum allowed size in octets of
            /// a plaintext.
            pub const P_MAX: u64 = $p_max;
            /// The maximum allowed size in octets of
            /// a ciphertext.
            pub const C_MAX: u64 = match Self::P_MAX.checked_add(Self::TAG_SIZE as u64) {
                Some(n) => n,
                None => unreachable!(),
            };
            /// The maximum allowed size in octets of additional
            /// authenticated data.
            pub const A_MAX: u64 = Self::P_MAX;
            /// The size in octets of a key.
            pub const KEY_SIZE: usize = $aes_bits / 8;
            /// The size in octets of a nonce.
            pub const NONCE_SIZE: usize = NONCE_SIZE;
            /// The size in octets of a tag.
            pub const TAG_SIZE: usize = $tag_bits / 8;

            /// Creates a new instance of AES-GCM-SST.
            #[inline]
            pub fn new(key: &[u8; $aes_bits / 8]) -> Self {
                let generator = KeyInit::new(key.into());
                Self(GcmSst::new(generator))
            }

            /// Encrypts and authenticates `plaintext`,
            /// authenticates `additional_data`, and writes the
            /// result to `dst`.
            ///
            /// # Requirements
            ///
            /// - `dst` must be at least as long as `plaintext`.
            #[inline]
            pub fn seal(
                &self,
                dst: &mut [u8],
                nonce: &Nonce,
                plaintext: &[u8],
                additional_data: &[u8],
            ) -> Result<Tag<{ Self::TAG_SIZE }>, Error> {
                if dst.len() < plaintext.len()
                    || !less_or_equal(plaintext.len(), Self::P_MAX)
                    || !less_or_equal(additional_data.len(), Self::A_MAX)
                {
                    Err(Error)
                } else {
                    self.0.seal(dst, nonce.into(), plaintext, additional_data)
                }
            }

            /// Encrypts and authenticates `data` in place and
            /// authenticates `additional_data`.
            #[inline]
            pub fn seal_in_place(
                &self,
                nonce: &Nonce,
                data: &mut [u8],
                additional_data: &[u8],
            ) -> Result<Tag<{ Self::TAG_SIZE }>, Error> {
                if !less_or_equal(data.len(), Self::P_MAX)
                    || !less_or_equal(additional_data.len(), Self::A_MAX)
                {
                    Err(Error)
                } else {
                    self.0.seal_in_place(nonce.into(), data, additional_data)
                }
            }

            /// Decrypts and authenticates `plaintext`,
            /// authenticates `additional_data`, and writes the
            /// result to `dst`.
            ///
            /// # Requirements
            ///
            /// - `dst` must be at least as long as `ciphertext`,
            ///   less the tag length.
            #[inline]
            pub fn open(
                &self,
                dst: &mut [u8],
                nonce: &Nonce,
                ciphertext: &[u8],
                tag: &Tag<{ Self::TAG_SIZE }>,
                additional_data: &[u8],
            ) -> Result<(), Error> {
                if dst.len() < ciphertext.len()
                    || !less_or_equal(ciphertext.len(), Self::C_MAX)
                    || !less_or_equal(additional_data.len(), Self::A_MAX)
                {
                    Err(Error)
                } else {
                    self.0
                        .open(dst, nonce.into(), ciphertext, tag, additional_data)
                }
            }

            /// Decrypts and authenticates `plaintext` in place
            /// and authenticates `additional_data`.
            #[inline]
            pub fn open_in_place(
                &self,
                nonce: &Nonce,
                data: &mut [u8],
                tag: &Tag<{ Self::TAG_SIZE }>,
                additional_data: &[u8],
            ) -> Result<(), Error> {
                if !less_or_equal(data.len(), Self::C_MAX)
                    || !less_or_equal(additional_data.len(), Self::A_MAX)
                {
                    Err(Error)
                } else {
                    self.0
                        .open_in_place(nonce.into(), data, tag, additional_data)
                }
            }
        }

        impl InnerUser for $name {
            type Inner = AesGcmSst<$aes, { Self::TAG_SIZE }>;
        }

        impl KeyInit for $name {
            #[inline]
            fn new(key: &Key<$aes>) -> Self {
                Self::new(key.as_ref())
            }
        }

        impl AeadCore for $name {
            type NonceSize = <<Self as InnerUser>::Inner as AeadCore>::NonceSize;
            type TagSize = <<Self as InnerUser>::Inner as AeadCore>::TagSize;
            type CiphertextOverhead = <<Self as InnerUser>::Inner as AeadCore>::CiphertextOverhead;
        }

        impl AeadInPlace for $name {
            //#[inline]
            fn encrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
            ) -> aead::Result<aead::Tag<Self>> {
                self.seal_in_place(nonce.as_ref(), buffer, associated_data)
                    .map(Into::into)
                    .map_err(Into::into)
            }

            //#[inline]
            fn decrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                buffer: &mut [u8],
                tag: &aead::Tag<Self>,
            ) -> aead::Result<()> {
                self.open_in_place(nonce.as_ref(), buffer, tag.as_ref(), associated_data)
                    .map_err(Into::into)
            }
        }
    };
}
pub(crate) use aead_impl;

aead_impl!(Aes128GcmSst4, Aes128, (1 << 36) - 48, 32, 128, "a four");
aead_impl!(Aes128GcmSst8, Aes128, (1 << 36) - 48, 64, 128, "an eight");
aead_impl!(Aes128GcmSst12, Aes128, 1 << 35, 96, 128, "a twelve");
aead_impl!(Aes128GcmSst14, Aes128, 1 << 19, 112, 128, "a fourteen");

aead_impl!(Aes256GcmSst4, Aes256, (1 << 36) - 48, 32, 256, "a four");
aead_impl!(Aes256GcmSst8, Aes256, (1 << 36) - 48, 64, 256, "an eight");
aead_impl!(Aes256GcmSst12, Aes256, 1 << 35, 96, 256, "a twelve");
aead_impl!(Aes256GcmSst14, Aes256, 1 << 19, 112, 256, "a fourteen");

/// Reports whether `x <= y`.
#[inline(always)]
fn less_or_equal(x: usize, y: u64) -> bool {
    u64::try_from(x).is_ok_and(|n| n <= y)
}
