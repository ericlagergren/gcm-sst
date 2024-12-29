#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use core::{fmt, marker::PhantomData};

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace,
};
use cipher::{
    crypto_common::InnerUser, Block, BlockCipher, BlockEncryptMut, BlockSizeUser, InnerIvInit, Iv,
    IvSizeUser, KeyInit, KeySizeUser, StreamCipher, StreamCipherCore,
};
use ctr::{flavors::CtrFlavor, CtrCore};
use inout::InOutBuf;
use typenum::{IsGreaterOrEqual, IsLessOrEqual, U16};

use crate::{Error, GcmSst, Generator, Keystream, MaxTagSize, MinTagSize, Nonce, NonceSize};

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
    fn next(&mut self) -> [u8; 16] {
        let mut block = [0; 16];
        self.apply_keystream(&mut block);
        block
    }

    fn apply(mut self, buf: InOutBuf<'_, '_, u8>) {
        self.apply_keystream_inout(buf)
    }
}

// impl<C> Generator for C
// where
//     for<'a> &'a C: BlockEncryptMut + BlockCipher<BlockSize = U16>,
// {
//     fn init(&self, nonce: &Nonce) -> impl Keystream {
//         InnerIvInit::inner_iv_init(self, nonce)
//     }
// }

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
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let cipher = G::new(key);
        Self::new(cipher)
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
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<aead::Tag<Self>> {
        self.seal_in_place(nonce, buffer, associated_data)
            .map_err(Into::into)
    }

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

/// Turns a TODO into a [`Generator`].
pub struct CtrGen<S, C> {
    cipher: C,
    _s: PhantomData<S>,
}

impl<S, C> CtrGen<S, C> {
    /// TODO
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            _s: PhantomData,
        }
    }
}

impl<S, C> Clone for CtrGen<S, C>
where
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            _s: PhantomData,
        }
    }
}

impl<S, C> fmt::Debug for CtrGen<S, C>
where
    C: fmt::Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CtrGen")
            .field("cipher", &self.cipher)
            .finish_non_exhaustive()
    }
}

impl<'a, S, C> Generator for CtrGen<S, &'a C>
where
    S: StreamCipher + InnerIvInit<Inner = &'a C, IvSize = NonceSize>,
{
    fn init(&self, nonce: &Nonce) -> impl Keystream {
        S::inner_iv_init(&self.cipher, &{
            let mut iv = Iv::<S>::default();
            iv[..12].copy_from_slice(nonce);
            iv
        })
    }
}

impl<S, C> KeySizeUser for CtrGen<S, C>
where
    C: KeySizeUser,
{
    type KeySize = C::KeySize;
}

impl<S, C> KeyInit for CtrGen<S, C>
where
    C: KeyInit,
{
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let cipher = C::new(key);
        Self::new(cipher)
    }
}
