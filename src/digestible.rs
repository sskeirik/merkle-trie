//! Defines a trait [`Digestible`] which can be hashed via [`Digest`] functions.

use crate::utils::to_hex;
use digest::{Digest, Output};

/// Hash-value wrapper struct that can pretty-print a truncated hash.
pub(crate) struct HashFrag<'a, H: Digest>(pub &'a Output<H>);
impl<'a, H: Digest> std::fmt::Display for HashFrag<'a, H> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let hash = &self.0;
        let hash_prefix = &hash[0..std::cmp::min(hash.len(), 4)];
        f.write_str(&to_hex::<false>(hash_prefix))
    }
}

/// Given a [`Digest`]-compatible hash, return the hash of the empty byte string.
pub fn empty_hash<H: Digest>() -> Output<H> {
    H::new().finalize()
}

/// Type that can serialized for use in a cryptographic [`Digest`].
pub trait Digestible {
    /// Serialize self and update hasher.
    fn update_hasher<D: Digest>(&self, hasher: &mut D);
}

/// Internal wrapper type for [`Digestible`] impls for debugging purposes.
///
/// NOTE: This is used because we do not want to commit users of this
///       crate to our particular digest implementations.
#[derive(Clone, PartialEq, Eq)]
#[allow(unused)] // debugging
pub(crate) struct W<T>(pub(crate) T);

impl<T: std::fmt::Debug> std::fmt::Debug for W<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

macro_rules! impl_digestible_numeric {
    ($($t:ty),*) => {
        $(impl Digestible for W<$t> {
            fn update_hasher<D: Digest>(&self, hasher: &mut D) {
                hasher.update(&self.0.to_le_bytes());
            }
        })*
    };
}

impl_digestible_numeric!(
    u8, u16, u32, u64, u128, i8, i16, i32, i64, i128, f32, f64, usize, isize
);

impl Digestible for W<bool> {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        W(self.0 as u8).update_hasher(hasher);
    }
}
