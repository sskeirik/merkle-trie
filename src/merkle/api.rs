use std::fmt::Debug;
use allocator_api2::alloc::Global;
use digest::{Digest, Output};
use crate::digestible::Digestible;
use crate::merkle::types::{Trie, TrieMode, Node, NodeLink, NodeUpdate, NodeUpsert};
use crate::merkle::types::mode::*;
use crate::utils::{Allocator, Box, copy_slice_into_box};

impl<T: Digestible, const N: usize, const K: usize, H: Digest> Trie<T,N,K,Global,H,Complete> {
    /// Create a new compressed Merkle trie using the global allocator
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Complete> {
    /// Create a new compressed Merkle trie using the given allocator
    pub fn new_in(alloc: A) -> Self {
        Trie(alloc, NodeLink(None))
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Trie<T,N,K,A,H,M> {
    /// Set the value of target_key in the trie
    #[must_use]
    pub fn update<U: NodeUpdate<T>>(&mut self, target_key: &[u8], updater: U) -> Result<(), &'static str> {
        let alloc = &self.0;
        // unlike other top-level functions, we need to ensure that case EmptySlot
        // is not reachable for the root node when calling probe_mut internally
        if self.1.0.is_none() {
            let value = updater.on_vacant().ok_or("Cannot set leaf with null initializer")?;
            let leaf = Node::new_leaf(copy_slice_into_box(target_key, alloc.clone()), value);
            self.1.0 = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
            Ok(())
        } else {
            self.1.update(target_key, updater, alloc.clone())
        }
    }

    /// Set the value of target_key in the trie
    #[must_use]
    pub fn set(&mut self, target_key: &[u8], value: T) -> Result<(), &'static str> {
        self.update(target_key, NodeUpsert { value })
    }

    /// Delete a non-opaque node from the tree and return its value
    pub fn delete(&mut self, target_key: &[u8]) -> Option<T> {
        self.1.delete(target_key, self.0.clone())
    }

    /// Return a reference to the value of search_key in the trie, if it exists
    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        self.1.get(search_key)
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
    /// collision is effectively impossible.
    pub fn weak_eq(&self, other: &Self) -> bool {
        self.digest() == other.digest()
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Complete> {
    /// Convert a concrete trie to a partial trie
    #[must_use]
    pub fn to_partial(self) -> Trie<T,N,K,A,H,Partial> {
        let alloc = self.0;
        let link = NodeLink(self.1.0.map(|(h,n)| (h, Node::to_partial_boxed(n))));
        Trie::<T,N,K,A,H,Partial>(alloc, link)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Partial> {
    /// Given a partial trie and a set of keys, compute the minimal partial trie
    /// proves the non/existence of each key in the set in the trie
    pub fn witness_for_keys(&mut self, keys: Vec<&[u8]>) {
        self.1.witness_for_keys(keys);
    }
}

/// The debug format of a Merkle trie is a nested presentation of the trie structure
impl<T: Digestible + Debug, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> std::fmt::Debug for Trie<T,N,K,A,H,M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.1.debug_fmt( 0, None, f)
    }
}

/// The digest of a Merkle trie is just the digest of its root hash
impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Digestible for Trie<T,N,K,A,H,M> {
    fn digest_update<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.digest());
    }
}