//! RustCrypto bindings.
//!
//! [RustCrypto]: https://github.com/rustcrypto

#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use core::{fmt, marker::PhantomData, slice};

pub use aead::generic_array::ArrayLength;
use aead::{generic_array::GenericArray, AeadCore, AeadInPlace};
use cipher::{
    BlockCipher, BlockEncrypt, InnerIvInit, Iv, Key, KeyInit, KeySizeUser, StreamCipherCore,
};
use ctr::{flavors::CtrFlavor, CtrCore};
use inout::InOutBuf;
use typenum::{
    generic_const_mappings::{Const, ToUInt, U},
    GrEq, IsGreaterOrEqual, IsLess, IsLessOrEqual, Le, LeEq, NonZero, Unsigned, U12, U16, U256,
};
#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Error, GcmSst, Generator, Keystream, MaxTagSize, MinTagSize, Nonce, NONCE_SIZE};

/// The size in octets of a GCM-SST nonce.
pub type NonceSize = U12;

impl From<Error> for aead::Error {
    #[inline]
    fn from(_: Error) -> Self {
        Self
    }
}

impl From<aead::Error> for Error {
    #[inline]
    fn from(_: aead::Error) -> Self {
        Self
    }
}

impl<S: StreamCipherCore<BlockSize = U16>> Keystream for S {
    #[inline]
    fn remaining_bytes(&self) -> Option<usize> {
        let blocks = self.remaining_blocks()?;
        blocks.checked_mul(S::BlockSize::USIZE)
    }

    #[inline]
    fn first(&mut self, buf: &mut [u8; 48]) {
        let (blocks, _) = as_chunks_mut::<S::BlockSize>(buf);
        self.write_keystream_blocks(blocks);
    }

    #[inline]
    fn apply(self, buf: InOutBuf<'_, '_, u8>) {
        let result = self.try_apply_keystream_partial(buf);
        debug_assert!(result.is_ok());
    }
}

impl<G, const T: usize> KeySizeUser for GcmSst<G, T>
where
    G: KeySizeUser,
{
    type KeySize = G::KeySize;
}

impl<G, const T: usize> KeyInit for GcmSst<G, T>
where
    G: KeyInit,
{
    #[inline]
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self::new(G::new(key))
    }
}

impl<G, const T: usize> AeadCore for GcmSst<G, T>
where
    Const<T>: ToUInt,
    U<T>: IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
    GrEq<U<T>, MinTagSize>: NonZero,
    LeEq<U<T>, MaxTagSize>: NonZero,
    U<T>: ArrayLength<u8>,
{
    type NonceSize = NonceSize;
    type TagSize = U<T>;
    type CiphertextOverhead = U<T>;
}

impl<G, const T: usize> AeadInPlace for GcmSst<G, T>
where
    G: Generator,

    Const<T>: ToUInt,
    U<T>: IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
    GrEq<U<T>, MinTagSize>: NonZero,
    LeEq<U<T>, MaxTagSize>: NonZero,
    U<T>: ArrayLength<u8>,
    [u8; T]: Into<aead::Tag<Self>>,
{
    #[inline]
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        #[allow(
            clippy::unwrap_used,
            reason = "The compiler can prove that `try_into` always succeeds"
        )]
        let nonce = nonce.as_slice().try_into().unwrap();
        let tag = self.seal_in_place(nonce, buffer, associated_data)?;
        Ok(tag.into())
    }

    #[inline]
    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
        #[allow(
            clippy::unwrap_used,
            reason = "The compiler can prove that `try_into` always succeeds"
        )]
        let nonce = nonce.as_slice().try_into().unwrap();
        #[allow(
            clippy::unwrap_used,
            reason = "The compiler can prove that `try_into` always succeeds"
        )]
        let tag = tag.as_slice().try_into().unwrap();
        self.open_in_place(nonce, buffer, tag, associated_data)
            .map_err(Into::into)
    }
}

/// A counter-mode [`Generator`].
pub struct CtrGen<C, F> {
    cipher: C,
    _flavor: PhantomData<F>,
}

impl<C, F> CtrGen<C, F> {
    /// Creates a `CtrGen`.
    #[inline]
    pub fn new(cipher: C) -> Self {
        Self {
            cipher,
            _flavor: PhantomData,
        }
    }
}

impl<C, F> Clone for CtrGen<C, F>
where
    C: Clone,
{
    #[inline]
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            _flavor: PhantomData,
        }
    }
}

impl<C, F> fmt::Debug for CtrGen<C, F>
where
    C: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtrGen")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl<C, F> Generator for CtrGen<C, F>
where
    C: BlockEncrypt + BlockCipher,
    C::BlockSize: IsLess<U256> + IsGreaterOrEqual<U12>,
    Le<C::BlockSize, U256>: NonZero,
    F: CtrFlavor<C::BlockSize>,
{
    type NonceSize = NonceSize;

    #[inline]
    fn init(&self, nonce: &Nonce) -> impl Keystream {
        let core = CtrCore::<_, F>::inner_iv_init(&self.cipher, &{
            let mut iv = Iv::<CtrCore<&C, F>>::default();
            #[allow(
                clippy::indexing_slicing,
                reason = "The compiler can prove that `NONCE_SIZE` is in bounds"
            )]
            iv[..NONCE_SIZE].copy_from_slice(nonce);
            iv
        });
        KeystreamWrapper::from_core(core)
    }
}

impl<C, F> KeySizeUser for CtrGen<C, F>
where
    C: KeySizeUser,
{
    type KeySize = C::KeySize;
}

impl<C, F> KeyInit for CtrGen<C, F>
where
    C: KeyInit,
{
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::new(C::new(key))
    }
}

/// A wrapper around [`StreamCipherCore`] that implements
/// [`Keystream`] for any block size.
// The code is largely taken from
// <https://github.com/RustCrypto/traits/blob/2b9e5f585a5fda5392ac81240ea5bfd9e2cc1790/cipher/src/stream/wrapper.rs>
pub struct KeystreamWrapper<T: StreamCipherCore> {
    core: T,
    // Buffered block.
    buffer: GenericArray<u8, T::BlockSize>,
}

impl<T: StreamCipherCore> KeystreamWrapper<T> {
    /// Crates a `KeystreamWrapper` from a [`StreamCipherCore`].
    #[allow(clippy::indexing_slicing)]
    pub fn from_core(core: T) -> Self {
        let mut buffer = GenericArray::default();
        buffer[0] = T::BlockSize::U8;
        Self { core, buffer }
    }
}

impl<T: StreamCipherCore> KeystreamWrapper<T> {
    #[inline]
    #[allow(clippy::indexing_slicing)]
    fn get_pos(&self) -> u8 {
        let pos = self.buffer[0];
        if pos == 0 || pos > T::BlockSize::U8 {
            debug_assert_ne!(pos, 0);
            debug_assert!(pos <= T::BlockSize::U8);

            // SAFETY: `pos` is set only to values smaller than
            // block size.
            unsafe { core::hint::unreachable_unchecked() }
        }
        pos
    }

    /// Set buffer position without checking that it's smaller
    /// than buffer size.
    ///
    /// # Safety
    ///
    /// `pos` MUST be bigger than zero and smaller or equal to
    /// `T::BlockSize::USIZE`.
    #[inline]
    #[allow(clippy::indexing_slicing)]
    unsafe fn set_pos_unchecked(&mut self, pos: usize) {
        debug_assert_ne!(pos, 0);
        debug_assert!(pos <= T::BlockSize::USIZE);

        self.buffer[0] = pos as u8;
    }

    /// Return number of remaining bytes in the internal buffer.
    #[inline]
    #[allow(clippy::arithmetic_side_effects)]
    fn remaining(&self) -> u8 {
        // This never underflows because of the safety invariant.
        T::BlockSize::U8 - self.get_pos()
    }

    fn check_remaining(&self, data_len: usize) -> Result<(), Error> {
        let rem_blocks = match self.core.remaining_blocks() {
            Some(v) => v,
            None => return Ok(()),
        };

        let buf_rem = usize::from(self.remaining());
        let data_len = match data_len.checked_sub(buf_rem) {
            Some(0) | None => return Ok(()),
            Some(res) => res,
        };

        let bs = T::BlockSize::USIZE;
        let blocks = data_len.div_ceil(bs);
        if blocks > rem_blocks {
            Err(Error)
        } else {
            Ok(())
        }
    }
}

impl<T: StreamCipherCore> Keystream for KeystreamWrapper<T> {
    #[inline]
    fn remaining_bytes(&self) -> Option<usize> {
        let blocks = self.core.remaining_blocks()?;
        let rem = usize::from(self.remaining());
        blocks.checked_mul(T::BlockSize::USIZE)?.checked_add(rem)
    }

    #[inline]
    #[allow(clippy::indexing_slicing)]
    fn first(&mut self, buf: &mut [u8; 48]) {
        debug_assert_eq!(self.check_remaining(buf.len()), Ok(()));

        let (blocks, tail) = as_chunks_mut::<T::BlockSize>(buf);
        self.core.write_keystream_blocks(blocks);

        let new_pos = if tail.is_empty() {
            T::BlockSize::USIZE
        } else {
            self.core.write_keystream_block(&mut self.buffer);
            tail.copy_from_slice(&self.buffer[..tail.len()]);
            tail.len()
        };
        // SAFETY: `as_chunks` always returns tail with size
        // less than block size. If `tail.len()` is zero, we
        // replace it with block size. Thus the invariant
        // required by `set_pos_unchecked` is satisfied.
        unsafe {
            self.set_pos_unchecked(new_pos);
        }
    }

    #[inline]
    #[allow(clippy::arithmetic_side_effects)]
    #[allow(clippy::indexing_slicing)]
    fn apply(mut self, mut data: InOutBuf<'_, '_, u8>) {
        debug_assert_eq!(self.check_remaining(data.len()), Ok(()));

        let pos = usize::from(self.get_pos());
        let rem = usize::from(self.remaining());
        let data_len = data.len();

        if rem != 0 {
            if data_len <= rem {
                data.xor_in2out(&self.buffer[pos..][..data_len]);
                // SAFETY: we have checked that `data_len` is
                // less or equal to length of remaining keystream
                // data, thus `pos + data_len` can not be bigger
                // than block size. Since `pos` is never zero,
                // `pos + data_len` can not be zero. Thus `pos
                // + data_len` satisfies the safety invariant
                // required by `set_pos_unchecked`.
                unsafe {
                    self.set_pos_unchecked(pos + data_len);
                }
                return;
            }
            let (mut left, right) = data.split_at(rem);
            data = right;
            left.xor_in2out(&self.buffer[pos..]);
        }

        let (blocks, mut tail) = data.into_chunks();
        self.core.apply_keystream_blocks_inout(blocks);

        let new_pos = if tail.is_empty() {
            T::BlockSize::USIZE
        } else {
            // Note that we temporarily write a pseudo-random
            // byte into the first byte of `self.buffer`. It may
            // break the safety invariant, but after XORing
            // keystream block with `tail`, we immediately
            // overwrite the first byte with a correct value.
            self.core.write_keystream_block(&mut self.buffer);
            tail.xor_in2out(&self.buffer[..tail.len()]);
            tail.len()
        };
        // SAFETY: `into_chunks` always returns tail with size
        // less than block size. If `tail.len()` is zero, we
        // replace it with block size. Thus the invariant
        // required by `set_pos_unchecked` is satisfied.
        unsafe {
            self.set_pos_unchecked(new_pos);
        }
    }
}

impl<T: KeySizeUser + StreamCipherCore> KeySizeUser for KeystreamWrapper<T> {
    type KeySize = T::KeySize;
}

impl<T: KeyInit + StreamCipherCore> KeyInit for KeystreamWrapper<T> {
    #[inline]
    fn new(key: &Key<Self>) -> Self {
        Self::from_core(T::new(key))
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<T: StreamCipherCore> Drop for KeystreamWrapper<T> {
    fn drop(&mut self) {
        // If present, `core` will be zeroized by its own `Drop`.
        self.buffer.zeroize();
    }
}

#[cfg(feature = "zeroize")]
#[cfg_attr(docsrs, doc(cfg(feature = "zeroize")))]
impl<T: StreamCipherCore + ZeroizeOnDrop> ZeroizeOnDrop for KeystreamWrapper<T> {}

// See https://doc.rust-lang.org/std/primitive.slice.html#method.as_chunks_mut
#[inline(always)]
#[allow(clippy::arithmetic_side_effects)]
fn as_chunks_mut<N: ArrayLength<u8>>(blocks: &mut [u8]) -> (&mut [GenericArray<u8, N>], &mut [u8]) {
    let len_rounded_down = (blocks.len() / N::USIZE) * N::USIZE;
    // SAFETY: The rounded-down value is always the same or
    // smaller than the original length, and thus must be
    // in-bounds of the slice.
    let (head, tail) = unsafe { blocks.split_at_mut_unchecked(len_rounded_down) };
    let new_len = head.len() / N::USIZE;
    // SAFETY: We cast a slice of `new_len * N` elements into
    // a slice of `new_len` many `N` elements chunks.
    let head = unsafe { slice::from_raw_parts_mut(head.as_mut_ptr().cast(), new_len) };
    (head, tail)
}
