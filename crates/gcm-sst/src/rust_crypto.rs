#![cfg(feature = "rust-crypto")]
#![cfg_attr(docsrs, doc(cfg(feature = "rust-crypto")))]

use core::{fmt, marker::PhantomData};

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore, AeadInPlace,
};
use cipher::{
    Block, BlockCipher, BlockEncryptMut, BlockSizeUser, InnerIvInit, KeyInit, KeySizeUser,
    StreamCipherCore,
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

impl<S> Keystream for S
where
    S: StreamCipherCore<BlockSize = U16>,
{
    fn next(&mut self) -> [u8; 16] {
        let mut block = Block::<S>::default();
        self.write_keystream_block(&mut block);
        block.into()
    }

    fn apply(self, buf: InOutBuf<'_, '_, u8>) {
        self.apply_keystream_partial(buf)
    }
}

// impl <S> Generator for S
// where S: Keystream + KeyIvInit {
//     fn init(&self, nonce:&Nonce)->Self {
//         Self::new()
//     }
// }

impl<C, T> KeySizeUser for GcmSst<C, T>
where
    C: KeySizeUser,
{
    type KeySize = C::KeySize;
}

impl<C, T> KeyInit for GcmSst<C, T>
where
    C: KeyInit,
{
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let cipher = C::new(key);
        Self::new(cipher)
    }
}

impl<C, T> AeadCore for GcmSst<C, T>
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
pub struct CtrGen<C, F> {
    cipher: C,
    _f: PhantomData<F>,
}

impl<C, F> CtrGen<C, F> {
    /// TODO
    pub const fn new(cipher: C) -> Self {
        Self {
            cipher,
            _f: PhantomData,
        }
    }
}

impl<C, F> Clone for CtrGen<C, F>
where
    C: Clone,
{
    fn clone(&self) -> Self {
        Self {
            cipher: self.cipher.clone(),
            _f: PhantomData,
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
    for<'a> &'a C: BlockEncryptMut + BlockCipher<BlockSize = U16>,
    for<'a> F: CtrFlavor<<&'a C as BlockSizeUser>::BlockSize>,
{
    fn init(&self, nonce: &Nonce) -> impl Keystream {
        CtrCore::<&C, F>::inner_iv_init(&self.cipher, &{
            let mut block = Block::<&C>::default();
            block[..12].copy_from_slice(nonce);
            block
        })
    }
}

// impl<T, C, F> From<T> for CtrGen<C, F> {
//     fn from(cipher: C) -> Self {
//         Self {
//             cipher,
//             _f: PhantomData,
//         }
//     }
// }

// impl Generator for Aes128 {
//     type Keystream = ();
//     fn init(&self, nonce: &Nonce) -> Self::Keystream {
//         Self::inner_iv_init((), &{
//             let mut block = Block::default();
//             block[..12].copy_from_slice(nonce);
//             block
//         })
//     }
// }

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
    fn new(key: &GenericArray<u8, Self::KeySize>) -> Self {
        let cipher = C::new(key);
        Self::new(cipher)
    }
}
