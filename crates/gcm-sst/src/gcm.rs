use core::{error, fmt, marker::PhantomData};

use inout::InOutBuf;
use polyhash::{Key as PolyKey, Lite, Polyval, Precomputed};
use subtle::ConstantTimeEq;
use typenum::{
    generic_const_mappings::{Const, ToUInt, U},
    GrEq, IsGreaterOrEqual, IsLessOrEqual, LeEq, NonZero, Unsigned, U16, U4,
};

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
    /// Reads the next `N` keystream bytes.
    fn next<const N: usize>(&mut self, buf: &mut [u8; N]);
    /// Applies the remainder of the keystream to `buf`.
    fn try_apply(self, buf: InOutBuf<'_, '_, u8>) -> Result<(), Error>;
}

/// The size in octets of a GCM-SST nonce.
pub const NONCE_SIZE: usize = 12;

/// The nonce used by GCM-SST.
pub type Nonce = [u8; NONCE_SIZE];

/// A GCM-SST authentication tag.
pub type Tag<const N: usize> = [u8; N];

/// The maximum size in octets of a GCM-SST authentication tag.
pub const MAX_TAG_SIZE: usize = 16;

/// The maximum size in octets of a GCM-SST authentication tag.
pub type MaxTagSize = U16;

/// The minimum size in octets of a GCM-SST authentication tag.
pub const MIN_TAG_SIZE: usize = 4;

/// The minimum size in octets of a GCM-SST authentication tag.
pub type MinTagSize = U4;

const _: () = {
    assert!(MIN_TAG_SIZE < MAX_TAG_SIZE);
    assert!(MIN_TAG_SIZE > 0);
    assert!(MaxTagSize::USIZE == MAX_TAG_SIZE);
    assert!(MinTagSize::USIZE == MIN_TAG_SIZE);
};

// Because we need to convert bytes to bits.
const P_MAX: u64 = u64::MAX / 8;
const C_MAX: u64 = u64::MAX / 8;
const A_MAX: u64 = u64::MAX / 8;

/// GCM-SST AEAD.
#[derive(Clone, Debug)]
pub struct GcmSst<G, const T: usize> {
    generator: G,
    _marker: PhantomData<G>,
}

impl<G, const T: usize> GcmSst<G, T> {
    /// Creates a new instance of GCM-SST.
    pub fn new(generator: G) -> Self {
        Self {
            generator,
            _marker: PhantomData,
        }
    }
}

impl<G, const T: usize> GcmSst<G, T>
where
    G: Generator,
    Const<T>: ToUInt,
    U<T>: IsGreaterOrEqual<MinTagSize> + IsLessOrEqual<MaxTagSize>,
    GrEq<U<T>, MinTagSize>: NonZero,
    LeEq<U<T>, MaxTagSize>: NonZero,
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
        if !less_or_equal(buf.len(), P_MAX) || !less_or_equal(ad.len(), A_MAX) {
            return Err(Error);
        }

        // Initiate keystream generator with K and N
        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let (h, q, m) = first_three_blocks(&mut ks)?;

        // Let ct = P ⊕ truncate(Z[3:n + 2], len(P))
        ks.try_apply(buf.reborrow())?;

        let tag = self.compute_tag(&h, &q, &m, buf.get_out(), ad);

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
        if !less_or_equal(buf.len(), C_MAX) || !less_or_equal(ad.len(), A_MAX) {
            return Err(Error);
        }
        let ct = buf.get_in();

        // Initiate keystream generator with K and N
        let mut ks = self.generator.init(nonce);

        // Let H = Z[0], Q = Z[1], M = Z[2]
        let (h, q, m) = first_three_blocks(&mut ks)?;

        // Let expected_tag = truncate(full_tag, tag_length)
        let expected_tag = self.compute_tag(&h, &q, &m, ct, ad);

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
    ) -> [u8; T] {
        // Let S = zeropad(A) || zeropad(ct) || LE64(len(ct)) || LE64(len(A))
        //
        // Let X = POLYVAL(H, S[0], S[1], ..., S[m + n - 1])
        let x = {
            let mut poly = Polyval::<Precomputed>::new(&PolyKey::new_unchecked(h));
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
        let full_tag = {
            let mut poly = Polyval::<Lite>::new(&PolyKey::new_unchecked(q));
            poly.update_block(&xor(x, l));
            xor(poly.tag().into(), *m)
        };

        // Let tag = truncate(full_tag, tag_length)
        let mut tag = [0; T];
        #[allow(
            clippy::indexing_slicing,
            reason = "The compiler can prove that `T` is in bounds"
        )]
        tag.copy_from_slice(&full_tag[..T]);
        tag
    }
}

#[inline(always)]
const fn xor(a: [u8; 16], b: [u8; 16]) -> [u8; 16] {
    // This appears to generate much better assembly than the
    // obvious iterator loop.
    let c = u128::from_ne_bytes(a) ^ u128::from_ne_bytes(b);
    c.to_ne_bytes()
}

/// Reports whether `x <= y`.
#[inline(always)]
fn less_or_equal(x: usize, y: u64) -> bool {
    u64::try_from(x).is_ok_and(|n| n <= y)
}

#[inline(always)]
fn first_three_blocks<K: Keystream>(ks: &mut K) -> Result<([u8; 16], [u8; 16], [u8; 16]), Error> {
    let mut buf = [0; 16 * 3];
    ks.next(&mut buf);
    let (h, rest) = buf.split_at(16);
    let (q, m) = rest.split_at(16);
    Ok((
        h.try_into().unwrap(),
        q.try_into().unwrap(),
        m.try_into().unwrap(),
    ))
}
