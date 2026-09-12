//! Merkle [`Trie`] type and its public API.

use crate::digestible::Digestible;
use crate::digestible::HashWitnessValue;
use crate::node::{Node, NodeLink, TrieMode, Complete, Partial};
use crate::utils::{Allocator, Box, copy_slice_into_box};
use allocator_api2::alloc::Global;
use digest::{Digest, Output};
use std::borrow::Borrow;
use std::fmt::Debug;

/// Errors that can occur while performing [`Trie`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrieError {
    /// The provided key was empty or exceeded the trie's maximum key length.
    InvalidKeyLength,
    /// A leaf could not be created because no initial value was supplied.
    MissingInitializer,
    /// The target key resolved to a node whose kind does not support this update.
    UnsupportedSet,
    /// The target key is a prefix of an existing key, or vice versa, so no value can be set there.
    SetOnPrefix,
}

impl std::fmt::Display for TrieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::InvalidKeyLength => "key length is invalid",
            Self::MissingInitializer => "cannot create leaf with null initializer",
            Self::UnsupportedSet => "unsupported trie set",
            Self::SetOnPrefix => "cannot set a value on a prefix",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for TrieError {}

/// Trait that describes how to update the value stored in a [`Trie`] node.
///
/// A [`std::collections::hash_map::Entry`]-style API does not work well
/// for Merkleized data structures (like our [`Trie`]) because returning
/// a mutable reference to a node means callers may inadvertantly invalidate
/// previously computed node hashes, requiring calls to [`Trie::digest`]
/// to rewalk the entire trie to ensure hash freshness.
///
/// Instead, we use a more heavyweight trait-based API that injects any
/// custom update logic into the execution of [`Trie::update`] itself, so that
/// our update function can recalculate node hashes as needed, once-and-for-all.
///
/// We compare our approach to two alternative approaches below:
///
/// 1. Use a pair of `Option<T>` and `FnOnce(&mut T)`.
///
///    This works _but_ memory must be duplicated between the two
///    values used for the vacant and occupied cases.
///
/// 2. Make [`NodeUpdate::on_occupied`] take a closure `FnOnce(&mut T)`.
///
///    This does not provide any extra generality (since we can
///    always represent custom logic via a new trait impl), and
///    we hit the same problem described in point (1).
pub trait NodeUpdate<T> {
    /// How to update a node value when a prior value already exists.
    ///
    /// It is the implementor's resposibility to ensure that this function
    /// actually overwrites the mutable input reference.
    ///
    /// If an implementation fails to conform to the above requirement,
    /// it will be sound, but useless for overwriting existing values.
    fn on_occupied(self, existing_value: &mut T);

    /// The value to insert if no value is currently present;
    /// Returning [None] will cause this operation to fail for non-existent values,
    /// enabling insert-without-overwriting semantics.
    fn on_vacant(self) -> Option<T>;
}

/// Implements [`NodeUpdate`] by upserting [`Self::value`].
pub(super) struct NodeUpsert<T> {
    /// The value to be upserted.
    pub value: T,
}

/// Updates a node's value by upsertion of the stored value.
impl<T> NodeUpdate<T> for NodeUpsert<T> {
    fn on_occupied(self, existing_value: &mut T) {
        *existing_value = self.value;
    }

    fn on_vacant(self) -> Option<T> {
        Some(self.value)
    }
}

/// A generic, compressed Merkleized trie.
///
/// We describe its generic paramters below:
///
/// | Param | Bounds                    | Description                                                                                |
/// | ---   | ---                       | ---                                                                                        |
/// | `T`   | [`Digestible`]            | The value type stored in this trie                                                         |
/// | `N`   | [`usize`]                 | Max key length in bytes                                                                    |
/// | `K`   | [`usize`]                 | Node branching factor (must choose 2,4,16, or 256 - powers of two ensure fast bitwise ops) |
/// | `H`   | [`Digest`]                | The hash function used for hash pointers                                                   |
/// | `A`   | [`Allocator`] + [`Clone`] | The allocator used to store keys/values/nodes                                              |
/// | `M`   | [`TrieMode`]              | Either [`Complete`] or [`Partial`] which enables `Opaque` nodes                            |
///
/// For dense tries, higher branching factors can reduce size overhead.
///
/// [`Trie`] always implements [`Debug`], eliding leaf values as `..`; use
/// [`Trie::debug_with_values`] to print them instead (requires `T: Debug`).
/// [`Trie`] implements [`Clone`] only if `T` does.
#[derive(Clone)]
pub struct Trie<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
>(pub(super) A, pub(super) NodeLink<T, N, K, H, A, M>);

impl<T: Digestible, const N: usize, const K: usize, H: Digest> Trie<T, N, K, H, Global, Complete> {
    /// Create a new compressed Merkle trie using the global allocator
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<T: Digestible + PartialEq + Eq, const N: usize, const K: usize, H: Digest> Default
    for Trie<T, N, K, H, Global, Complete>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    Trie<T, N, K, H, A, Complete>
{
    /// Create a new compressed Merkle trie using the given allocator
    pub fn new_in(alloc: A) -> Self {
        Trie(alloc, NodeLink(None))
    }
}

impl<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>
    Trie<T, N, K, H, A, M>
{
    /// Set the value of target_key in the trie
    pub fn update<U: NodeUpdate<T>>(
        &mut self,
        target_key: &[u8],
        updater: U,
    ) -> Result<(), TrieError> {
        Self::check_key(target_key)?;
        let alloc = &self.0;
        // unlike other top-level functions, we need to ensure that case EmptySlot
        // is not reachable for the root node when calling probe_mut internally
        if self.1.0.is_none() {
            let value = updater.on_vacant().ok_or(TrieError::MissingInitializer)?;
            let leaf = Node::new_leaf(copy_slice_into_box(target_key, alloc.clone()), value);
            self.1.0 = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
            Ok(())
        } else {
            self.1.update(target_key, updater, alloc.clone())
        }
    }

    /// Set the value of target_key in the trie
    pub fn set(&mut self, target_key: &[u8], value: T) -> Result<(), TrieError> {
        Self::check_key(target_key)?;
        self.update(target_key, NodeUpsert { value })
    }

    /// Delete a non-opaque node from the tree and return its value
    pub fn delete(&mut self, target_key: &[u8]) -> Result<Option<T>, TrieError> {
        Self::check_key(target_key)?;
        Ok(self.1.delete(target_key, self.0.clone()))
    }

    /// Return a reference to the value of search_key in the trie, if it exists
    pub fn get<'a>(&'a self, target_key: &[u8]) -> Result<Option<&'a T>, TrieError> {
        Self::check_key(target_key)?;
        Ok(self.1.get(target_key))
    }

    /// Given an iterator of (key, expected_presence) pairs,
    /// return an iterator where each value is either:
    ///
    /// - `Err()` indicating an ill-formed input error,
    /// - `Ok(None)` indicating key's presence/absence was expected
    /// - `Ok(Some((idx,true)))` indicating key's presence/absence was unexpected,
    /// - `Ok(Some((idx,false)))` indicating key's presence/absence is unknown,
    /// 
    /// Note that the final case is only possible for [`Partial`] tries
    /// where some nodes have been pruned.
    pub fn verify_each_key<'a>(
        &'a self,
        keys_and_expected: impl Iterator<Item = (&'a [u8], Option<bool>)> + 'a,
    ) -> impl Iterator<Item = Result<Option<bool>, TrieError>> + 'a {
        keys_and_expected.map(|(target_key, expected)| {
            Self::check_key(target_key)?;
            let found = self.1.verify(target_key);
            if found != expected {
                Ok(Some(found.is_some()))
            } else {
                Ok(None)
            }
        })
    }

    /// Given a target keys vector and an expected presence vector,
    /// return true iff each key's presence in the trie provably matches its expected presence, where:
    /// - Some(false) - indicates a key's absence is expected
    /// - Some(true)  - indicates a key's presence is expected
    /// - None        - indicates a key's presence/absence is unprovable
    /// return false otherwise or if any key has an invalid length.
    pub fn verify_keys<'a>(&self, target_keys: impl Borrow<Vec<&'a [u8]>>, expected: impl Borrow<Vec<Option<bool>>>) -> bool {
        let (target_keys,expected) = (target_keys.borrow(), expected.borrow());
        if target_keys.len() != expected.len() {
            return false
        }
        let iter = target_keys.iter().copied().zip(expected.iter().copied());
        self.verify_each_key(iter).all(|res| res.is_ok_and(|opt| opt.is_none()))
    }

    /// Return the digest of the trie
    pub fn digest(&self) -> Output<H> {
        self.1.stored_digest()
    }

    /// Check equality between tries via hash root equality;
    /// unlike true equality, this equality only holds probabilistically
    /// with very high probability (assuming a proper cryptographic hash
    /// function is chosen for H).
    ///
    /// With a properly chosen cryptographic hash function, finding a
    /// collision, i.e., a case where:
    ///
    /// `( self.digest() == other.digest() ) != ( self == digest )`
    ///
    /// is effectively impossible.
    pub fn hash_eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }

    /// Ensure that argument keys satisfy this [`Trie`]'s length restrictions
    #[inline]
    fn check_key(key: &[u8]) -> Result<(), TrieError> {
        if key.is_empty() || key.len() > N {
            Err(TrieError::InvalidKeyLength)
        } else {
            Ok(())
        }
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    Trie<T, N, K, H, A, Complete>
{
    /// Convert a concrete trie to a partial trie
    #[must_use]
    pub fn to_partial(self) -> Trie<T, N, K, H, A, Partial> {
        Trie::<T, N, K, H, A, Partial>(self.0, self.1.into_partial())
    }

    /// Given a complete trie and a set of keys, build the minimal partial trie that
    /// proves the non/existence of each key in the set in the trie, representing
    /// values outside the witness by their digest rather than requiring `T: Clone`.
    pub fn to_hash_witness_for_keys(&self, keys: Vec<&[u8]>) -> Trie<HashWitnessValue<H>, N, K, H, A, Partial> {
        let witness_root = self.1.to_hash_witness_for_keys(keys, self.0.clone());
        Trie(self.0.clone(), witness_root)
    }
}

impl<T: Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    Trie<T, N, K, H, A, Complete>
{
    /// Given a complete, cloneable trie and a set of keys, build the minimal partial trie
    /// proves the non/existence of each key in the set in the trie
    pub fn to_witness_for_keys(&self, keys: Vec<&[u8]>) -> Trie<T, N, K, H, A, Partial> {
        let witness_root = self.1.to_witness_for_keys(keys, self.0.clone());
        Trie(self.0.clone(), witness_root)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    Trie<T, N, K, H, A, Partial>
{
    /// Given a partial trie and a set of keys, update this trie in-place to obtain a minimal partial trie that
    /// proves the non/existence of each key in the set in the trie
    pub fn prune_for_keys(&mut self, keys: Vec<&[u8]>) {
        self.1.prune_for_keys(keys);
    }
}

/// Trie equality is just equality of its node structure
impl<
    T: Digestible + PartialEq + Eq,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> PartialEq for Trie<T, N, K, H, A, M>
{
    fn eq(&self, other: &Self) -> bool {
        self.1 == other.1
    }
}

/// The debug format of a Merkle trie is a nested presentation of the trie structure;
/// leaf values are elided as `..` (see [`Trie::debug_with_values`] to print them).
impl<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> Debug for Trie<T, N, K, H, A, M>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.1.debug_fmt(0, None, f)
    }
}

/// Wrapper returned by [`Trie::debug_with_values`].
struct DebugWithValues<
    'a,
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
>(&'a Trie<T, N, K, H, A, M>);

impl<
    'a,
    T: Digestible + Debug,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> Debug for DebugWithValues<'a, T, N, K, H, A, M>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.1.debug_fmt_verbose(0, None, f)
    }
}

impl<
    T: Digestible + Debug,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> Trie<T, N, K, H, A, M>
{
    /// Returns a [`Debug`]-formattable view of this trie that prints each leaf's
    /// actual value via `T`'s [`Debug`] impl, unlike `{:?}` on [`Trie`] itself (which
    /// elides leaf values as `..` but works for any `T`).
    pub fn debug_with_values(&self) -> impl Debug + '_ {
        DebugWithValues(self)
    }
}

/// The digest of a Merkle trie is just the digest of its root hash
impl<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>
    Digestible for Trie<T, N, K, H, A, M>
{
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.digest());
    }
}
