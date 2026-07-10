use std::fmt::Debug;
use allocator_api2::alloc::Global;
use digest::{Digest, Output};
use crate::digestible::{Digestible, empty_hash};
use crate::merkle::types::{Trie, TrieMode, Node, NodeUpdate, Kind, Concrete, Partial, SimpleUpdate};
use crate::utils::{Allocator, copy_slice_into_box};

impl<T: Digestible, const N: usize, const K: usize, H: Digest> Trie<T,N,K,Global,H,Concrete> {
    /// Create a new compressed Merkle trie using the global allocator
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Concrete> {
    /// Create a new compressed Merkle trie using the given allocator
    pub fn new_in(alloc: A) -> Self {
        Trie(alloc, None)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Trie<T,N,K,A,H,M> {
    /// Set the value of target_key in the trie
    #[must_use]
    pub fn update<U: NodeUpdate<T>>(&mut self, target_key: &[u8], updater: U) -> Result<(), &'static str> {
        let alloc = &self.0;
        if let Some((hash, node)) = self.1.as_mut() {
            node.update(Some(hash), target_key, updater, alloc.clone())?;
        } else {
            let Some(value) = updater.on_vacant() else {
                return Err("Cannot create leaf with null initializer")
            };
            let key = copy_slice_into_box(target_key, alloc.clone());
            let node = Node { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }};
            self.1 = Some((node.digest(), node));
        }
        Ok(())
    }

    /// Set the value of target_key in the trie
    #[must_use]
    pub fn set(&mut self, target_key: &[u8], value: T) -> Result<(), &'static str> {
        self.update(target_key, SimpleUpdate(value))
    }

    /// Return a reference to the value of search_key in the trie, if it exists
    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        self.1.as_ref().map(|(_hash, node)| node.get(search_key))?
    }

    /// Return the digest of the trie
    pub fn digest(&self) -> Output<H> {
        self.1.as_ref().map_or(empty_hash::<H>(), |(hash, _node)| hash.clone())
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Concrete> {
    /// Convert a concrete trie to a partial trie
    #[must_use]
    pub fn to_partial(self) -> Trie<T,N,K,A,H,Partial> {
        Trie::<T,N,K,A,H,Partial>(self.0, self.1.map(|(hash,node)| (hash, node.to_partial())))
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Partial> {
    /// Given a partial trie and a set of keys, compute the minimal partial trie
    /// proves the non/existence of each key in the set in the trie
    pub fn witness_for_keys(&mut self, keys: Vec<&[u8]>) {
        self.1.as_mut().map(|(_hash,node)| node.witness_for_keys(keys));
    }
}

/// The debug format of a Merkle trie is a nested presentation of the trie structure
impl<T: Digestible + Debug, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> std::fmt::Debug for Trie<T,N,K,A,H,M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Node::<T,N,K,A,H,M>::debug_fmt(&self.1, 0, None, f)
    }
}

/// The digest of a Merkle trie is just the digest of its root hash
impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Digestible for Trie<T,N,K,A,H,M> {
    fn digest_update<D: Digest>(&self, hasher: &mut D) {
        hasher.update(self.digest());
    }
}