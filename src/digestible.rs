//! Defines a trait [`Digestible`] which can be hashed via [`Digest`] functions.
//! 
//! Additionally defines [`Digestible`] impls for basic types.

use digest::{Digest, Output};
use either::Either;
use crate::utils::to_hex;

/// Hash-value wrapper struct that can pretty-print a truncated hash
pub struct HashFrag<'a, H: Digest>(pub &'a Output<H>);
impl<'a, H: Digest> std::fmt::Display for HashFrag<'a,H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = &self.0;
        let hash_prefix = &hash[0..std::cmp::min(hash.len(),4)];
        f.write_str(&to_hex::<false>(hash_prefix))
    }
}

/// Given a [`Digest`]-compatible hash, return the hash of the empty byte string
pub fn empty_hash<H: Digest>() -> Output<H> {
    H::new().finalize()
}

/// Type that can serialized for use in a cryptographic [`Digest`].
pub trait Digestible {
    /// Serialize self and update hasher
    fn update_hasher<D: Digest>(&self, hasher: &mut D);
}

macro_rules! impl_digestible_numeric {
    ($($t:ty),*) => {
        $(impl Digestible for $t {
            fn update_hasher<D: Digest>(&self, hasher: &mut D) {
                hasher.update(&self.to_le_bytes());
            }
        })*
    };
}

impl_digestible_numeric!(u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64, usize, isize);

impl Digestible for bool {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        (*self as u8).update_hasher(hasher);
    }
}

impl <T: Digestible> Digestible for Box<T> {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        (**self).update_hasher(hasher);
    }
}

impl<const N: usize> Digestible for [u8; N] {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.as_slice());
    }
}

impl<S: digest::array::ArraySize> Digestible for digest::array::Array<u8, S> {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.as_slice());
    }
}

impl<L: Digestible, R: Digestible> Digestible for Either<L, R> {
    fn update_hasher<D: digest::Digest>(&self, hasher: &mut D) {
        match self {
            Either::Left(l)  => { hasher.update(&[0u8]); l.update_hasher(hasher); }
            Either::Right(r) => { hasher.update(&[1u8]); r.update_hasher(hasher); }
        }
    }
}