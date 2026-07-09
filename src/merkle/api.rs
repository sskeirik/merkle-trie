use std::fmt::Debug;
use allocator_api2::alloc::Global;
use digest::{Digest, Output};
use crate::digestible::{Digestible, empty_hash};
use crate::merkle::types::{Trie, TrieMode, Node, NodeUpdate, Kind, Concrete, Partial, SimpleUpdate};
use crate::utils::{Allocator, copy_slice_into_box};
// for debugging
#[allow(unused_imports)]
use {
    tracing::{instrument, debug},
    crate::trace_val,
    crate::utils::{to_ascii, to_bin, to_hex},
};

impl<T: Digestible, const N: usize, const K: usize, H: Digest> Trie<T,N,K,Global,H,Concrete> {
    pub fn new() -> Self {
        Self::new_in(Global)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Concrete> {
    pub fn new_in(alloc: A) -> Self {
        Trie(alloc, None)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Trie<T,N,K,A,H,M> {
    #[must_use]
    pub fn update<U: NodeUpdate<T>>(&mut self, search_key: &[u8], updater: U) -> Result<(), &'static str> {
        let alloc = &self.0;
        if let Some((hash, node)) = self.1.as_mut() {
            node.update(Some(hash), search_key, updater, alloc.clone())?;
        } else {
            let Some(value) = updater.on_vacant() else {
                return Err("Cannot create leaf with null initializer")
            };
            let key = copy_slice_into_box(search_key, alloc.clone());
            let node = Node { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }};
            self.1 = Some((node.digest(), node));
        }
        Ok(())
    }

    #[must_use]
    pub fn set(&mut self, search_key: &[u8], value: T) -> Result<(), &'static str> {
        self.update(search_key, SimpleUpdate(value))
    }

    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        self.1.as_ref().map(|(_hash, node)| node.get(search_key))?
    }

    pub fn digest(&self) -> Output<H> {
        self.1.as_ref().map_or(empty_hash::<H>(), |(hash, _node)| hash.clone())
    }
}

impl<T: Digestible + Debug, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> std::fmt::Debug for Trie<T,N,K,A,H,M> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        Node::<T,N,K,A,H,M>::debug_fmt(&self.1, 0, None, f)
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Concrete> {
    #[must_use]
    pub fn to_partial(self) -> Trie<T,N,K,A,H,Partial> {
        Trie::<T,N,K,A,H,Partial>(self.0, self.1.map(|(hash,node)| (hash, node.to_partial())))
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Trie<T,N,K,A,H,Partial> {
    pub fn witness_for_keys(&mut self, keys: Vec<&[u8]>) {
        self.1.as_mut().map(|(_hash,node)| node.witness_for_keys(keys));
    }
}