use core::{marker::PhantomData, option::Option, result::Result};

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, Error,
};
pub use aead::{Key, Tag};
use cfg_if::cfg_if;
use cipher::{
    BlockCipher, BlockEncrypt, BlockEncryptMut, BlockSizeUser, InnerIvInit, KeyInit,
    StreamCipherCore,
};
use ctr::CtrCore;
use inout::InOutBuf;
use polyhash::{Key as PolyKey, Polyval};
use subtle::ConstantTimeEq;
use typenum::{IsGreaterOrEqual, IsLessOrEqual, U12, U16, U4};

type Block = GenericArray<u8, U16>;

/// The nonce used by GCM-SST.
pub type Nonce = GenericArray<u8, U12>;

/// A cipher using GCM-SST mode.
#[derive(Clone)]
pub struct GcmSst<A, T> {
    cipher: A,
    _tag: PhantomData<T>,
}

impl<A, T> GcmSst<A, T>
where
    T: ArrayLength<u8> + IsGreaterOrEqual<U4> + IsLessOrEqual<U16>,
{
    /// The maximum size in octets of a plaintext.
    pub const P_MAX: u64 = (1 << 36) - 48;
    /// The maximum size in octets of a ciphertext.
    pub const C_MAX: u64 = Self::P_MAX + Self::TAG_SIZE as u64;
    /// The maximum size in octets of the additional data.
    pub const A_MAX: u64 = 1 << 36;
    /// The size in octets of a nonce.
    pub const NONCE_SIZE: usize = 12;
    /// The size in octets of a tag.
    pub const TAG_SIZE: usize = T::USIZE;
}

impl<A, T> AeadCore for GcmSst<A, T>
where
    T: ArrayLength<u8> + IsGreaterOrEqual<U4> + IsLessOrEqual<U16>,
{
    type NonceSize = U12;
    type TagSize = T;
    type CiphertextOverhead = T;
}

impl<A, T> GcmSst<A, T>
where
    A: BlockSizeUser<BlockSize = U16> + BlockEncrypt + KeyInit,
{
    /// Creates a new instance of GCM-SST.
    pub fn new(key: &Key<A>) -> Self {
        Self {
            cipher: A::new(key),
            _tag: PhantomData,
        }
    }
}

impl<A, T> GcmSst<A, T>
where
    A: BlockCipher + BlockSizeUser<BlockSize = U16> + BlockEncrypt,
    T: ArrayLength<u8> + IsGreaterOrEqual<U4> + IsLessOrEqual<U16>,
{
    /// Encrypts and authenticates `plaintext`, authenticates
    /// `additional_data`, and writes the result to `dst`.
    ///
    /// # Requirements
    ///
    /// - `dst` must be at least as long as `plaintext`.
    /// - `plaintext` must be at most [`P_MAX`][Self::P_MAX]
    /// octets long.
    /// - `additional_data` must be at most
    /// [`A_MAX`][Self::A_MAX] octets long.
    #[inline]
    pub fn seal(
        &self,
        dst: &mut [u8],
        nonce: &Nonce,
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> aead::Result<Tag<Self>> {
        self.encrypt(dst, nonce, plaintext, additional_data)
    }

    fn encrypt(
        &self,
        ct: &mut [u8],
        nonce: &Nonce,
        pt: &[u8],
        ad: &[u8],
    ) -> aead::Result<Tag<Self>> {
        if pt.len() as u64 > Self::P_MAX || ad.len() as u64 > Self::A_MAX {
            return Err(Error);
        }
        let ct = ct.get_mut(..pt.len()).ok_or(Error)?;

        let mut ks = Ctr32BE::inner_iv_init(&self.cipher, &{
            let mut block = Block::default();
            block[..12].copy_from_slice(nonce);
            block
        });

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next_keystream_block();
        let q = ks.next_keystream_block();
        let m = ks.next_keystream_block();

        // Let ct = P XOR truncate(Z[3:n + 2], len(P))
        ks.apply_keystream_partial(InOutBuf::new(pt, ct).assume("`ct.len()` == `pt.len()`")?);

        // Let tag = truncate(full_tag, tag_length)
        let tag = {
            // Let S = zeropad(A) || zeropad(ct) || LE64(len(ct)) || LE64(len(A))
            //
            // Let full_tag = POLYVAL(Q, X XOR S[m + n]) XOR M
            let full_tag: Block = {
                // Let X = POLYVAL(H, S[0], S[1], ..., S[m + n - 1])
                let x = {
                    let mut poly =
                        Polyval::new(&PolyKey::new(&h.into()).assume("`h` is non-zero")?);
                    poly.update_padded(ad); // zeropad(A)
                    poly.update_padded(ct); // zeropad(ct)
                    poly.tag().into()
                };

                let s_m_n = {
                    let mut block = Block::default();
                    let (ct_len, ad_len) = block.split_at_mut(8);
                    ct_len.copy_from_slice(&(ct.len() as u64 * 8).to_le_bytes()); // LE64(len(ct))
                    ad_len.copy_from_slice(&(ad.len() as u64 * 8).to_le_bytes()); // LE64(len(A))
                    block.into()
                };

                let poly = {
                    let mut poly =
                        Polyval::new(&PolyKey::new(&q.into()).assume("`q` is non-zero")?);
                    poly.update(&xor(&x, &s_m_n))
                        .assume("`x ^ s[m+n]` is exactly `BLOCK_SIZE` bytes long")?;
                    poly.tag().into()
                };
                xor(&poly, &m.into())
            };

            let mut tag = Tag::<Self>::default();
            tag.copy_from_slice(&full_tag[..Self::TAG_SIZE]);
            tag
        };

        // Return (ct, tag)
        Ok(tag)
    }

    /// Decrypts and authenticates `plaintext`, authenticates
    /// `additional_data`, and writes the result to `dst`.
    ///
    /// # Requirements
    ///
    /// - `dst` must be at least as long as `ciphertext`.
    /// - `ciphertext` must be at most [`C_MAX`][Self::C_MAX]
    /// octets long.
    /// - `additional_data` must be at most
    /// [`A_MAX`][Self::A_MAX] octets long.
    #[inline]
    pub fn open(
        &self,
        dst: &mut [u8],
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag<Self>,
        additional_data: &[u8],
    ) -> aead::Result<()> {
        self.decrypt(dst, nonce, ciphertext, tag, additional_data)
    }

    fn decrypt(
        &self,
        pt: &mut [u8],
        nonce: &Nonce,
        ct: &[u8],
        tag: &Tag<Self>,
        ad: &[u8],
    ) -> aead::Result<()> {
        if ct.len() as u64 > Self::C_MAX || ad.len() as u64 > Self::A_MAX {
            return Err(Error);
        }
        let pt = pt.get_mut(..ct.len()).ok_or(Error)?;

        let mut ks = Ctr32BE::inner_iv_init(&self.cipher, &{
            let mut block = Block::default();
            block[..12].copy_from_slice(nonce);
            block
        });

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next_keystream_block();
        let q = ks.next_keystream_block();
        let m = ks.next_keystream_block();

        // Let S = zeropad(A) || zeropad(ct) || LE64(len(ct)) || LE64(len(A))
        //
        // Let full_tag = POLYVAL(Q, X XOR S[m + n]) XOR M
        let full_tag: Block = {
            // Let X = POLYVAL(H, S[0], S[1], ..., S[m + n - 1])
            let x = {
                let mut poly = Polyval::new(&PolyKey::new(&h.into()).assume("`h` is non-zero")?);
                poly.update_padded(ad); // zeropad(A)
                poly.update_padded(ct); // zeropad(ct)
                poly.tag().into()
            };

            let s_m_n = {
                let mut block = Block::default();
                let (ct_len, ad_len) = block.split_at_mut(8);
                ct_len.copy_from_slice(&(ct.len() as u64 * 8).to_le_bytes()); // LE64(len(ct))
                ad_len.copy_from_slice(&(ad.len() as u64 * 8).to_le_bytes()); // LE64(len(A))
                block.into()
            };

            let poly = {
                let mut poly = Polyval::new(&PolyKey::new(&q.into()).assume("`q` is non-zero")?);
                poly.update(&xor(&x, &s_m_n))
                    .assume("`x ^ s[m+n]` is exactly `BLOCK_SIZE` bytes long")?;
                poly.tag().into()
            };
            xor(&poly, &m.into())
        };
        // Let expected_tag = truncate(full_tag, tag_length)
        // If tag != expected_tag, return error and abort
        if !bool::from(full_tag[..Self::TAG_SIZE].ct_eq(tag)) {
            return Err(Error);
        }

        // Let P = ct XOR truncate(Z[3:n + 2], len(ct))
        ks.apply_keystream_partial(InOutBuf::new(ct, pt).assume("`ct.len()` == `pt.len()`")?);

        Ok(())
    }
}

/// Returns x^y.
#[inline(always)]
fn xor(x: &[u8; 16], y: &[u8; 16]) -> Block {
    let mut z = Block::default();
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
    z
}

type Ctr32BE<A> = CtrCore<A, ctr::flavors::Ctr32BE>;

trait StreamCipherCoreExt {
    fn next_keystream_block(&mut self) -> Block;
}

impl<A> StreamCipherCoreExt for Ctr32BE<A>
where
    A: BlockEncryptMut + BlockCipher + BlockSizeUser<BlockSize = U16>,
{
    #[inline(always)]
    fn next_keystream_block(&mut self) -> Block {
        let mut block = Block::default();
        self.write_keystream_block(&mut block);
        block
    }
}

impl From<Bug> for Error {
    fn from(_err: Bug) -> Self {
        Self
    }
}

#[derive(Debug)]
struct Bug;

impl Bug {
    #[cold]
    #[track_caller]
    fn new(_msg: &'static str) -> Self {
        cfg_if! {
            if #[cfg(debug_assertions)] {
                Self
            } else {
                #![allow(clippy::disallowed_macros)]
                unreachable!("{_msg}");
            }
        }
    }
}

trait BugExt<T> {
    fn assume(self, msg: &'static str) -> Result<T, Bug>;
}

impl<T> BugExt<T> for Option<T> {
    #[track_caller]
    fn assume(self, msg: &'static str) -> Result<T, Bug> {
        match self {
            Some(v) => Ok(v),
            None => Err(Bug::new(msg)),
        }
    }
}

impl<T, E> BugExt<T> for Result<T, E> {
    #[track_caller]
    fn assume(self, msg: &'static str) -> Result<T, Bug> {
        match self {
            Ok(v) => Ok(v),
            Err(_) => Err(Bug::new(msg)),
        }
    }
}
