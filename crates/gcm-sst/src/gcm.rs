use core::{error, fmt, marker::PhantomData};

pub use generic_array::ArrayLength;
use generic_array::GenericArray;
use inout::InOutBuf;
use polyhash::{Key as PolyKey, Lite, Polyval};
use subtle::ConstantTimeEq;
use typenum::{GrEq, IsGreaterOrEqual, IsLessOrEqual, LeEq, NonZero, Unsigned, U12, U16, U4};

/// An error returned by [`GcmSst`].
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Error;

impl error::Error for Error {}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "GCM-SST error")
    }
}

/// A keystream generator.
pub trait Generator {
    /// Uses `nonce` to generate a new keystream.
    fn init(&self, nonce: &Nonce) -> impl Keystream;
}

/// A stream of pseudorandom bytes.
pub trait Keystream: Sized {
    /// Applies the keystream to `buf`.
    fn try_apply(&mut self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error>;
}

trait KeystreamExt: Keystream {
    /// Returns the next keystream block.
    #[inline]
    fn next(&mut self) -> Result<[u8; 16], Error> {
        let mut block = [0; 16];
        self.try_apply(InOutBuf::from(&mut block[..]))?;
        Ok(block)
    }
}

impl<S: Keystream> KeystreamExt for S {}

/// The size in octets of a GCM-SST nonce.
pub const NONCE_SIZE: usize = NonceSize::USIZE;

/// The size in octets of a GCM-SST nonce.
pub type NonceSize = U12;

/// The nonce used by GCM-SST.
pub type Nonce = GenericArray<u8, NonceSize>;

/// A GCM-SST authentication tag.
pub type Tag<N> = GenericArray<u8, N>;

/// The maximum size in octets of a GCM-SST authentication tag.
pub const MAX_TAG_SIZE: usize = MaxTagSize::USIZE;

/// The maximum size in octets of a GCM-SST authentication tag.
pub type MaxTagSize = U16;

/// The minimum size in octets of a GCM-SST authentication tag.
pub const MIN_TAG_SIZE: usize = MinTagSize::USIZE;

/// The minimum size in octets of a GCM-SST authentication tag.
pub type MinTagSize = U4;

const P_MAX: u64 = u64::MAX / 8;
const C_MAX: u64 = u64::MAX / 8;
const A_MAX: u64 = u64::MAX / 8;

/// GCM-SST AEAD.
#[derive(Debug)]
pub struct GcmSst<G, T> {
    generator: G,
    _marker: PhantomData<(G, T)>,
}

impl<G, T> GcmSst<G, T> {
    /// Creates a new instance of GCM-SST.
    pub fn new(generator: G) -> Self {
        Self {
            generator,
            _marker: PhantomData,
        }
    }
}

impl<G, T> GcmSst<G, T>
where
    G: Generator,
    T: ArrayLength<u8> + IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
    GrEq<T, MinTagSize>: NonZero,
    LeEq<T, MaxTagSize>: NonZero,
{
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
        if !u64::try_from(buf.len()).is_ok_and(|n| n <= P_MAX)
            || !u64::try_from(ad.len()).is_ok_and(|n| n <= A_MAX)
        {
            return Err(Error);
        }

        // Initiate keystream generator with K and N
        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next()?;
        let q = ks.next()?;
        let m = ks.next()?;

        // Let ct = P ⊕ truncate(Z[3:n + 2], len(P))
        ks.try_apply(buf.reborrow())?;
        let ct = buf.get_out();

        // Let tag = truncate(full_tag, tag_length)
        let tag = {
            let full_tag = self.compute_tag(&h, &q, &m, ct, ad);

            // Let tag = truncate(full_tag, tag_length)
            let mut tag = Tag::default();
            #[allow(
                clippy::indexing_slicing,
                reason = "The compiler can prove that `T::USIZE` is in bounds"
            )]
            tag.copy_from_slice(&full_tag[..T::USIZE]);
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
    /// - `dst` must be at least as long as `ciphertext`, less
    ///    the tag length.
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
        if !u64::try_from(buf.len()).is_ok_and(|n| n <= C_MAX)
            || !u64::try_from(ad.len()).is_ok_and(|n| n <= A_MAX)
        {
            return Err(Error);
        }

        let ct = buf.get_in();
        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let h = ks.next()?;
        let q = ks.next()?;
        let m = ks.next()?;

        let full_tag = self.compute_tag(&h, &q, &m, ct, ad);
        #[allow(
            clippy::indexing_slicing,
            reason = "The compiler can prove that `T::USIZE` is in bounds"
        )]
        let expected_tag = &full_tag[..T::USIZE];

        // Let expected_tag = truncate(full_tag, tag_length)
        // If tag != expected_tag, return error and abort
        if !bool::from(expected_tag.ct_eq(tag)) {
            return Err(Error);
        }

        // Let P = ct XOR truncate(Z[3:n + 2], len(ct))
        ks.try_apply(buf)?;

        Ok(())
    }

    fn compute_tag(
        &self,
        h: &[u8; 16],
        q: &[u8; 16],
        m: &[u8; 16],
        ct: &[u8],
        ad: &[u8],
    ) -> [u8; 16] {
        // Let S = zeropad(A) || zeropad(ct) || LE64(len(ct)) || LE64(len(A))
        //
        // Let X = POLYVAL(H, S[0], S[1], ..., S[m + n - 1])
        let x = {
            let mut poly = Polyval::<Lite>::new(&PolyKey::new_unchecked(h));
            poly.update_padded(ad); // zeropad(A)
            poly.update_padded(ct); // zeropad(ct)
            poly.tag().into()
        };

        // Let L = LE64(len(ct)) || LE64(len(A))
        let l = {
            #[allow(
                clippy::arithmetic_side_effects,
                reason = "`encrypt` and `decrypt` check the length of `ct` and `ad`"
            )]
            let chunk = ((ct.len() as u128) * 8) | ((ad.len() as u128) * 8) << 64;
            chunk.to_le_bytes()
        };

        // Let full_tag = POLYVAL(Q, X XOR S[m + n]) XOR M
        let poly = {
            let mut poly = Polyval::<Lite>::new(&PolyKey::new_unchecked(q));
            poly.update_block(&xor(x, l));
            poly.tag().into()
        };
        xor(poly, *m)
    }
}

impl<G, T> Clone for GcmSst<G, T>
where
    G: Clone,
{
    fn clone(&self) -> Self {
        Self {
            generator: self.generator.clone(),
            _marker: PhantomData,
        }
    }
}

#[inline(always)]
const fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    // This appears to generate much better assembly than the
    // obvious iterator loop.
    let c = u128::from_ne_bytes(a) ^ u128::from_ne_bytes(b);
    c.to_ne_bytes()
}
