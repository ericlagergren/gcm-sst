#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use core::{fmt, marker::PhantomData};

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace,
};
use cipher::{
    BlockCipher, BlockEncrypt, InnerIvInit, Iv, KeyInit, KeySizeUser, StreamCipher,
    StreamCipherCoreWrapper,
};
use ctr::{flavors::CtrFlavor, CtrCore};
use inout::InOutBuf;
use typenum::{GrEq, IsGreaterOrEqual, IsLess, IsLessOrEqual, Le, LeEq, NonZero, U12, U256};

use crate::{
    Error, GcmSst, Generator, Keystream, MaxTagSize, MinTagSize, Nonce, NonceSize, NONCE_SIZE,
};

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

impl<S: StreamCipher> Keystream for S {
    #[inline]
    fn try_apply(&mut self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error> {
        self.try_apply_keystream_inout(buf).map_err(|_| Error)
    }
}

impl<G, T> KeySizeUser for GcmSst<G, T>
where
    G: KeySizeUser,
{
    type KeySize = G::KeySize;
}

impl<G, T> KeyInit for GcmSst<G, T>
where
    G: KeyInit,
{
    #[inline]
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self::new(G::new(key))
    }
}

impl<G, T> AeadCore for GcmSst<G, T>
where
    T: ArrayLength<u8> + IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
{
    type NonceSize = NonceSize;
    type TagSize = T;
    type CiphertextOverhead = T;
}

impl<G, T> AeadInPlace for GcmSst<G, T>
where
    G: Generator,
    T: ArrayLength<u8> + IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
    GrEq<T, MinTagSize>: NonZero,
    LeEq<T, MaxTagSize>: NonZero,
{
    #[inline]
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        self.seal_in_place(nonce, buffer, associated_data)
            .map_err(Into::into)
    }

    #[inline]
    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &aead::Tag<Self>,
    ) -> aead::Result<()> {
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
    /// Creates a `CtrCore`.
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
        StreamCipherCoreWrapper::from_core(core)
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
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        Self::new(C::new(key))
    }
}
