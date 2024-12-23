use core::{fmt, marker::PhantomData};

use cfg_if::cfg_if;
pub use crypto_common::generic_array::ArrayLength;
use crypto_common::generic_array::GenericArray;
use inout::InOutBuf;
use polyhash::{Key as PolyKey, Polyval};
use subtle::ConstantTimeEq;
use typenum::{IsGreaterOrEqual, IsLessOrEqual, Unsigned, U12, U16, U4};

/// An error returned by [`GcmSst`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AES-GCM-SST error")
    }
}

/// A keystream generator.
pub trait Generator {
    /// Uses `nonce` to generate a new keystream.
    fn init(&self, nonce: &Nonce) -> impl Keystream;
}

/// A stream of pseudorandom bytes.
pub trait Keystream {
    /// The keystream block.
    type Block: Into<[u8; 16]>;

    /// Returns the next keystream block.
    fn next(&mut self) -> Self::Block;

    /// Applies the remainder of the keystream to `buf`.
    fn apply(self, buf: InOutBuf<'_, '_, u8>);
}

/// A 128-bit chunk.
type Chunk = GenericArray<u8, U16>;

/// TODO
pub const NONCE_SIZE: usize = <NonceSize as Unsigned>::USIZE;

/// TODO
pub type NonceSize = U12;

/// The nonce used by GCM-SST.
pub type Nonce = GenericArray<u8, NonceSize>;

/// An authentication tag.
pub type Tag<N> = GenericArray<u8, N>;

/// A cipher using GCM-SST mode.
#[derive(Clone)]
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
    T: ArrayLength<u8> + IsGreaterOrEqual<U4> + IsLessOrEqual<U16>,
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
        self.encrypt(dst, nonce, plaintext, additional_data)
    }

    fn encrypt(&self, ct: &mut [u8], nonce: &Nonce, pt: &[u8], ad: &[u8]) -> Result<Tag<T>, Error> {
        let ct = ct.get_mut(..pt.len()).ok_or(Error)?;

        // Initiate keystream generator with K and N
        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next();
        let q = ks.next();
        let m = ks.next();

        // Let ct = P ⊕ truncate(Z[3:n + 2], len(P))
        ks.apply(InOutBuf::new(pt, ct).assume("`ct.len()` == `pt.len()`")?);

        // Let tag = truncate(full_tag, tag_length)
        let tag = {
            // Let full_tag = POLYVAL(Q, X ⊕ L) ⊕ M
            let full_tag: Chunk = {
                // Let S = zeropad(A) || zeropad(ct)
                // Let X = POLYVAL(H, S[0], S[1], ...)
                let x = {
                    let mut poly = Polyval::new(&PolyKey::new_unchecked(&h.into()));
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
                    u128::from_le_bytes(chunk.into())
                };

                let poly = {
                    let mut poly = Polyval::new(&PolyKey::new_unchecked(&q.into()));
                    poly.update_block(&(x ^ l).to_le_bytes());
                    poly.tag().into()
                };
                xor(&poly, &m.into())
            };

            // Let tag = truncate(full_tag, tag_length)
            let mut tag = Tag::default();
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
        tag: &Tag<T>,
        additional_data: &[u8],
    ) -> Result<(), Error> {
        self.decrypt(dst, nonce, ciphertext, tag, additional_data)
    }

    fn decrypt(
        &self,
        pt: &mut [u8],
        nonce: &Nonce,
        ct: &[u8],
        tag: &Tag<T>,
        ad: &[u8],
    ) -> Result<(), Error> {
        // if ct.len() as u64 > Self::C_MAX || ad.len() as u64 > Self::A_MAX {
        //     return Err(Error);
        // }
        let pt = pt.get_mut(..ct.len()).ok_or(Error)?;

        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next();
        let q = ks.next();
        let m = ks.next();

        // Let S = zeropad(A) || zeropad(ct) || LE64(len(ct)) || LE64(len(A))
        //
        // Let full_tag = POLYVAL(Q, X XOR S[m + n]) XOR M
        let full_tag: Chunk = {
            // Let X = POLYVAL(H, S[0], S[1], ..., S[m + n - 1])
            let x = {
                let mut poly = Polyval::new(&PolyKey::new(&h.into()).assume("`h` is non-zero")?);
                poly.update_padded(ad); // zeropad(A)
                poly.update_padded(ct); // zeropad(ct)
                poly.tag().into()
            };

            let s_m_n = {
                let mut chunk = Chunk::default();
                let (ct_len, ad_len) = chunk.split_at_mut(8);
                ct_len.copy_from_slice(&(ct.len() as u64 * 8).to_le_bytes()); // LE64(len(ct))
                ad_len.copy_from_slice(&(ad.len() as u64 * 8).to_le_bytes()); // LE64(len(A))
                chunk.into()
            };

            let poly = {
                let mut poly = Polyval::new(&PolyKey::new(&q.into()).assume("`q` is non-zero")?);
                poly.update_block(&xor(&x, &s_m_n).into());
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
        ks.apply(InOutBuf::new(ct, pt).assume("`ct.len()` == `pt.len()`")?);

        Ok(())
    }
}

/// Returns x^y.
#[inline(always)]
fn xor(x: &[u8; 16], y: &[u8; 16]) -> Chunk {
    let mut z = Chunk::default();
    for ((z, x), y) in z.iter_mut().zip(x).zip(y) {
        *z = x ^ y;
    }
    z
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
