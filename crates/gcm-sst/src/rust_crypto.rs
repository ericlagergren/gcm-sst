#![cfg(feature = "rust-crypto")]

use core::marker::PhantomData;

use aead::{
    generic_array::{ArrayLength, GenericArray},
    AeadCore,
};
use cipher::{
    Block, BlockCipher, BlockEncryptMut, BlockSizeUser, InnerIvInit, KeyInit, KeySizeUser,
    StreamCipherCore,
};
use ctr::{flavors::CtrFlavor, CtrCore};
use inout::InOutBuf;
use typenum::{U12, U16};

use crate::{GcmSst, Generator, Keystream, Nonce};

impl<C, T> AeadCore for GcmSst<C, T>
where
    T: ArrayLength<u8>,
{
    type NonceSize = U12;
    type TagSize = T;
    type CiphertextOverhead = T;
}

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

/// TODO
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

impl<C, F> Keystream for CtrCore<C, F>
where
    C: BlockEncryptMut + BlockCipher<BlockSize = U16>,
    F: CtrFlavor<C::BlockSize>,
{
    type Block = Block<C>;

    fn next(&mut self) -> Self::Block {
        let mut block = Self::Block::default();
        self.write_keystream_block(&mut block);
        block
    }

    fn apply(self, buf: InOutBuf<'_, '_, u8>) {
        self.apply_keystream_partial(buf)
    }
}

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
