use core::{fmt, marker::PhantomData};

pub use crypto_common::generic_array::ArrayLength;
use crypto_common::generic_array::GenericArray;
use inout::InOutBuf;
use polyhash::{Key as PolyKey, Lite, Polyval};
use subtle::ConstantTimeEq;
use typenum::{generic_const_mappings::U, IsGreaterOrEqual, IsLessOrEqual, U16};

/// An error returned by [`GcmSst`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AES-GCM-SST error")
    }
}

/// TODO
pub trait IntoGenerator {
    /// TODO
    type Generator;

    /// TODO
    fn into_generator(self) -> Self::Generator;
}

impl<G: Generator> IntoGenerator for G {
    type Generator = Self;

    #[inline]
    fn into_generator(self) -> Self::Generator {
        self
    }
}

/// A keystream generator.
pub trait Generator {
    /// Uses `nonce` to generate a new keystream.
    fn init(&self, nonce: &Nonce) -> impl Keystream;
}

/// A stream of pseudorandom bytes.
pub trait Keystream: Sized {
    /// Returns the next keystream block.
    fn next(&mut self) -> [u8; 16];

    /// Applies the remainder of the keystream to `buf`.
    fn apply(mut self, buf: InOutBuf<'_, '_, u8>) {
        let (mut head, mut tail) = buf.into_chunks::<U16>();
        for chunk in head.get_out() {
            let block = self.next();
            for (z, x) in chunk.iter_mut().zip(block.iter()) {
                *z ^= x;
            }
        }
        if !tail.is_empty() {
            let block = self.next();
            for (z, x) in tail.get_out().iter_mut().zip(block.iter()) {
                *z ^= x;
            }
        }
    }
}

/// TODO
pub const NONCE_SIZE: usize = 12;

/// TODO
pub type NonceSize = U<{ NONCE_SIZE }>;

/// The nonce used by GCM-SST.
pub type Nonce = GenericArray<u8, NonceSize>;

/// An authentication tag.
pub type Tag<N> = GenericArray<u8, N>;

/// TODO
pub const MAX_TAG_SIZE: usize = 16;

/// TODO
pub type MaxTagSize = U<{ MAX_TAG_SIZE }>;

/// TODO
pub const MIN_TAG_SIZE: usize = 16;

/// TODO
pub type MinTagSize = U<{ MIN_TAG_SIZE }>;

/// A cipher using GCM-SST mode.
#[derive(Debug)]
pub struct GcmSst<G, T> {
    generator: G,
    _tag: PhantomData<T>,
}

impl<G, T> GcmSst<G, T> {
    /// Creates a new instance of GCM-SST.
    pub const fn new(generator: G) -> Self {
        Self {
            generator,
            _tag: PhantomData,
        }
    }
}

impl<G, T> GcmSst<G, T>
where
    G: Generator,
    T: ArrayLength<u8> + IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
{
    const TAG_SIZE: usize = T::USIZE;

    /// Encrypts and authenticates `plaintext`, authenticates
    /// `additional_data`, and writes the result to `dst`.
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
    ) -> Result<Tag<T>, Error> {
        let ciphertext = dst.get_mut(..plaintext.len()).ok_or(Error)?;
        let buf = InOutBuf::new(plaintext, ciphertext).map_err(|_| Error)?;
        self.encrypt(nonce, buf, additional_data)
    }

    /// Encrypts and authenticates `data` in place and
    /// authenticates `additional_data`.
    #[inline]
    pub fn seal_in_place(
        &self,
        nonce: &Nonce,
        data: &mut [u8],
        additional_data: &[u8],
    ) -> Result<Tag<T>, Error> {
        self.encrypt(nonce, data.into(), additional_data)
    }

    fn encrypt(
        &self,
        nonce: &Nonce,
        mut buf: InOutBuf<'_, '_, u8>,
        ad: &[u8],
    ) -> Result<Tag<T>, Error> {
        // Initiate keystream generator with K and N
        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next();
        let q = ks.next();
        let m = ks.next();

        // Let ct = P ⊕ truncate(Z[3:n + 2], len(P))
        ks.apply(buf.reborrow());
        let ct = buf.get_out();

        // Let tag = truncate(full_tag, tag_length)
        let tag = {
            // Let full_tag = POLYVAL(Q, X ⊕ L) ⊕ M
            let full_tag = {
                // Let S = zeropad(A) || zeropad(ct)
                // Let X = POLYVAL(H, S[0], S[1], ...)
                let x = {
                    let mut poly = Polyval::<Lite>::new(&PolyKey::new_unchecked(&h.into()));
                    poly.update_padded(ad); // zeropad(A)
                    poly.update_padded(ct); // zeropad(ct)
                    u128::from_le_bytes(poly.tag().into())
                };

                // Let L = LE64(len(ct)) || LE64(len(A))
                let l = {
                    let mut chunk = [0; 16];
                    let (ct_len, ad_len) = chunk.split_at_mut(8);
                    ct_len.copy_from_slice(&(ct.len() as u64 * 8).to_le_bytes()); // LE64(len(ct))
                    ad_len.copy_from_slice(&(ad.len() as u64 * 8).to_le_bytes()); // LE64(len(A))
                    u128::from_le_bytes(chunk)
                };

                let poly = {
                    let mut poly = Polyval::<Lite>::new(&PolyKey::new_unchecked(&q.into()));
                    poly.update_block(&(x ^ l).to_le_bytes());
                    u128::from_le_bytes(poly.tag().into())
                };
                poly ^ u128::from_le_bytes(m)
            };

            // Let tag = truncate(full_tag, tag_length)
            let mut tag = Tag::default();
            tag.copy_from_slice(&full_tag.to_le_bytes()[..Self::TAG_SIZE]);
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
    #[inline]
    pub fn open(
        &self,
        dst: &mut [u8],
        nonce: &Nonce,
        ciphertext: &[u8],
        tag: &Tag<T>,
        additional_data: &[u8],
    ) -> Result<(), Error> {
        let plaintext = dst.get_mut(..ciphertext.len()).ok_or(Error)?;
        let buf = InOutBuf::new(ciphertext, plaintext).map_err(|_| Error)?;
        self.decrypt(nonce, buf, tag, additional_data)
    }

    /// Decrypts and authenticates `plaintext` in place and
    /// authenticates `additional_data`.
    #[inline]
    pub fn open_in_place(
        &self,
        nonce: &Nonce,
        data: &mut [u8],
        tag: &Tag<T>,
        additional_data: &[u8],
    ) -> Result<(), Error> {
        self.decrypt(nonce, data.into(), tag, additional_data)
    }

    fn decrypt(
        &self,
        nonce: &Nonce,
        buf: InOutBuf<'_, '_, u8>,
        tag: &Tag<T>,
        ad: &[u8],
    ) -> Result<(), Error> {
        let ct = buf.get_in();

        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next();
        let q = ks.next();
        let m = ks.next();

        // Let S = zeropad(A) || zeropad(ct) || LE64(len(ct)) || LE64(len(A))
        //
        // Let full_tag = POLYVAL(Q, X XOR S[m + n]) XOR M
        let full_tag = {
            // Let X = POLYVAL(H, S[0], S[1], ..., S[m + n - 1])
            let x = {
                let mut poly =
                    Polyval::<Lite>::new(&PolyKey::new(&h.into()).assume("`h` is non-zero")?);
                poly.update_padded(ad); // zeropad(A)
                poly.update_padded(ct); // zeropad(ct)
                u128::from_le_bytes(poly.tag().into())
            };

            let s_m_n = {
                let mut chunk = [0; 16];
                let (ct_len, ad_len) = chunk.split_at_mut(8);
                ct_len.copy_from_slice(&(ct.len() as u64 * 8).to_le_bytes()); // LE64(len(ct))
                ad_len.copy_from_slice(&(ad.len() as u64 * 8).to_le_bytes()); // LE64(len(A))
                u128::from_le_bytes(chunk)
            };

            let poly = {
                let mut poly =
                    Polyval::<Lite>::new(&PolyKey::new(&q.into()).assume("`q` is non-zero")?);
                poly.update_block(&(x ^ s_m_n).to_le_bytes());
                u128::from_le_bytes(poly.tag().into())
            };
            poly ^ u128::from_le_bytes(m)
        };
        // Let expected_tag = truncate(full_tag, tag_length)
        // If tag != expected_tag, return error and abort
        if !bool::from(full_tag.to_le_bytes()[..Self::TAG_SIZE].ct_eq(tag)) {
            return Err(Error);
        }

        // Let P = ct XOR truncate(Z[3:n + 2], len(ct))
        ks.apply(buf);

        Ok(())
    }
}

impl<G, T> Clone for GcmSst<G, T>
where
    G: Clone,
{
    fn clone(&self) -> Self {
        Self {
            generator: self.generator.clone(),
            _tag: PhantomData,
        }
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
        #[cfg(not(debug_assertions))]
        {
            Self
        }
        #[cfg(debug_assertions)]
        {
            unreachable!("{_msg}");
        }
    }
}

trait BugExt<T> {
    fn assume(self, msg: &'static str) -> Result<T, Bug>;
}

impl<T> BugExt<T> for Option<T> {
    #[inline]
    #[track_caller]
    fn assume(self, msg: &'static str) -> Result<T, Bug> {
        match self {
            Some(v) => Ok(v),
            None => Err(Bug::new(msg)),
        }
    }
}

impl<T, E> BugExt<T> for Result<T, E> {
    #[inline]
    #[track_caller]
    fn assume(self, msg: &'static str) -> Result<T, Bug> {
        match self {
            Ok(v) => Ok(v),
            Err(_) => Err(Bug::new(msg)),
        }
    }
}
