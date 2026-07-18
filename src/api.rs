//! Merkle [`Trie`] public API.
use allocator_api2::alloc::Global;
use digest::{Digest, Output};
use crate::digestible::Digestible;
use crate::types::{Trie, TrieMode, Node, NodeLink, NodeUpdate, NodeUpsert, TrieError};
use crate::types::mode::*;
use crate::utils::{Allocator, Box, copy_slice_into_box};

impl<T: Digestible, const N: usize, const K: usize, H: Digest> Trie<T,N,K,H,Global,Complete> {
    /// Create a new compressed Merkle trie using the global allocator
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,H,A,Complete> {
    /// Create a new compressed Merkle trie using the given allocator
    pub fn new_in(alloc: A) -> Self {
        Trie(alloc, NodeLink(None))
    }
}

impl<T: Digestible, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> Trie<T,N,K,H,A,M> {
    /// Set the value of target_key in the trie
    #[must_use]
    pub fn update<U: NodeUpdate<T>>(&mut self, target_key: &[u8], updater: U) -> Result<(), TrieError> {
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
    #[must_use]
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
    #[must_use]
    fn check_key(key: &[u8]) -> Result<(), TrieError> {
        if key.len() == 0 || key.len() > N {
            Err(TrieError::InvalidKeyLength)
        } else {
            Ok(())
        }
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,H,A,Complete> {
    /// Convert a concrete trie to a partial trie
    #[must_use]
    pub fn to_partial(self) -> Trie<T,N,K,H,A,Partial> {
        Trie::<T,N,K,H,A,Partial>(self.0, self.1.to_partial())
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,H,A,Partial> {
    /// Given a partial trie and a set of keys, compute the minimal partial trie
    /// proves the non/existence of each key in the set in the trie
    pub fn witness_for_keys(&mut self, keys: Vec<&[u8]>) {
        self.1.witness_for_keys(keys);
    }
}