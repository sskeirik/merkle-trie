/// Defines the Merkle Trie operations
use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Debug;
use digest::{Digest, Output};
use crate::digestible::{Digestible, empty_hash};
use crate::merkle::types::{TrieMode, Node, NodeUpdate, Kind, BranchData};
use crate::merkle::types::mode::*;
use crate::utils::{Allocator, Box, pick_mut_unchecked};
use crate::bitseqops::{BitDiff, BitPosition, BitSeqOps, find_first_distinct_bits};
#[allow(unused_imports)] // debugging
use {
    tracing::{instrument, debug},
    crate::trace_val,
    crate::utils::{to_ascii, to_bin, to_hex},
};

/// Represents why a probe result terminated
pub(crate) enum ProbeResult<N,B> {
    /// An exact match for the probe key was found at N
    ExactMatch(N),
    /// An empty child slot corresponding to the probe key was found at B
    EmptySlot(B, usize),
    /// A disagreement between the probe key and an existing node key was found at N
    Disagreement(N, BitDiff),
    /// An empty child slot corresponding to the probe key was found
    /// but could not be explored due to a depth bound due to the depth bound
    /// being reached
    Bounded(BitPosition, N, usize),
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Node<T,N,K,A,H,M> {

    /// Probes the trie, optionally with a bound, applying a user-specified action when the probe terminates
    #[instrument(level="debug", skip(self, bound, key, action))]
    pub(crate) fn probe<'a, R>(&'a self, mut bound: Option<usize>, key: &[u8], pos: BitPosition, action: impl FnOnce(BitPosition, ProbeResult<&'a Self, &'a BranchData<T,N,K,A,H,M>>) -> R) -> R {
        let label = if cfg!(debug_assertions) { self.debug_label() } else { const { String::new() } };

        let Some(split) = find_first_distinct_bits(&key[pos.index..], &self.key, pos.bits, None, Some(self.get_key_bits())) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(self))
        };

        match (&self.kind, split.prefix) {
            (Kind::Branch(branch), Some(1)) => {
                let slot = split.mask_value::<K>(key);
                if let Some((_hash, child)) = branch.children[slot].as_ref() {
                    match bound {
                        Some(0) => {
                            debug!("For {}, search bound hit at node {}", to_ascii(key), label);
                            return action(pos, ProbeResult::Bounded(split.pos, self, slot))
                        }
                        Some(ref mut n) => *n -= 1,
                        _ => {}
                    };
                    child.probe(bound, key, split.pos, action)
                } else {
                    debug!("For {}, empty slot found at branch {}", to_ascii(key), label);
                    action(pos, ProbeResult::EmptySlot(branch,slot))
                }
            },
            // no subtrie to explore, return
            _ => {
                debug!("For {}, disagreement {split:?} found at node {}", to_ascii(key), self.debug_label());
                action(pos, ProbeResult::Disagreement(self, split))
            }
        }
    }

    /// Probes the trie mutably, optionally with a bound, applying a user-specified action when the probe terminates that may modify the trie
    #[instrument(level="debug", skip(self, bound, key, action))]
    pub(crate) fn probe_mut<R>(&mut self, mut bound: Option<usize>, hash: Option<&mut Output<H>>, key: &[u8], pos: BitPosition, action: impl for <'a> FnOnce(BitPosition, ProbeResult<&'a mut Self, &'a mut BranchData<T,N,K,A,H,M>>) -> R) -> R {
        let label = if cfg!(debug_assertions) { self.debug_label() } else { const { String::new() } };

        let Some(split) = find_first_distinct_bits(&key[pos.index..], &self.key, pos.bits, None, Some(self.get_key_bits())) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(self))
        };

        let result = match (&mut self.kind, split.prefix) {
            (Kind::Branch(branch), Some(1)) => {
                let slot = split.mask_value::<K>(key);
                if let Some((hash, child)) = branch.children[slot].as_mut() {
                    match bound {
                        Some(0) => {
                            debug!("For {}, search bound hit at node {}", to_ascii(key), label);
                            return action(pos, ProbeResult::Bounded(split.pos, self, slot))
                        }
                        Some(ref mut n) => *n -= 1,
                        _ => {}
                    };
                    child.probe_mut(bound, Some(hash), key, split.pos, action)
                } else {
                    debug!("For {}, empty slot found at branch {}", to_ascii(key), label);
                    action(pos, ProbeResult::EmptySlot(branch, slot))
                }
            },
            // no subtrie to explore, return
            _ => {
                debug!("For {}, disagreement {split:?} found at node {}", to_ascii(key), label);
                action(pos, ProbeResult::Disagreement(self, split))
            }
        };
        // fixup our hash if we have one
        hash.map(|h| *h = self.digest());
        result
    }

    /// Given key_suffix, find existing descendant node that matches key_suffix and set its value to new_value
    /// otherwise, if matching descendant node does not exist, create one and set its value to new_value
    pub fn update<U: NodeUpdate<T>>(&mut self, hash: Option<&mut Output<H>>, target_key: &[u8], updater: U, alloc: A) -> Result<(), &'static str> {
        use Kind::*;
        use ProbeResult::*;
        let action = move |pos: BitPosition, find_result: ProbeResult<&mut Self, &mut BranchData<T,N,K,A,H,M>>| {
            match find_result {
                EmptySlot(branch, slot) => {
                    if let Some(value) = updater.on_vacant() {
                        let key = BitSeqOps::<K>::write_aligned_suffix::<A>(&pos, target_key, alloc.clone());
                        let leaf = Self::new_leaf(key, value);
                        branch.children[slot] = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
                        Ok(())
                    } else {
                        Err("Cannot create leaf with null initializer")
                    }
                }
                ExactMatch(Node { kind: Leaf { value, .. }, .. }) => Ok(updater.on_occupied(value)),
                Disagreement(existing, split) => {
                    if split.prefix.is_some() {
                        return Err("Cannot set a value on a prefix");
                    }
                    let Some(new_value) = updater.on_vacant() else {
                        return Err("Cannot create leaf with null initializer")
                    };
                    // create keys/slots for to to-be-installed branch
                    let new_branch_key = split.write_prefix::<K,A>(&existing.key, alloc.clone());
                    let new_existing_key = split.write_suffix::<K,A>(&existing.key, alloc.clone());
                    let inserted_leaf_key = split.write_suffix::<K,A>(target_key, alloc.clone());
                    let new_existing_slot = split.mask_value::<K>(&existing.key);
                    let inserted_leaf_slot = split.mask_value::<K>(target_key);
                    // evict existing, install new branch
                    let new_branch = Self::new_branch(new_branch_key, split.mask::<K>());
                    let mut evicted = std::mem::replace(existing, new_branch);
                    let installed_branch = existing;
                    // ready nodes for insertion
                    let inserted_leaf = Self::new_leaf(inserted_leaf_key, new_value);
                    evicted.key = new_existing_key;
                    unsafe {
                        installed_branch.raw_set_child(new_existing_slot, evicted, None, alloc.clone())?;
                        installed_branch.raw_set_child(inserted_leaf_slot, inserted_leaf, None, alloc.clone())?;
                    }
                    Ok(())
                }
                Bounded(..) => unreachable!("Bound not set"),
                _ => Err("Unsupported trie set")
            }
        };
        self.probe_mut(None, hash, target_key, BitPosition { index: 0, bits: 0 }, action)
    }

    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        use ProbeResult::*;
        let action = |_pos, result: ProbeResult<&'a Self, &'a BranchData<T,N,K,A,H,M>>| {
            match result {
                ExactMatch(Node { kind: Kind::Leaf { value, .. }, .. }) => Some(value),
                Bounded(..) => unreachable!("Bound not set"),
                _ => None,
            }
        };
        self.probe(None, search_key, BitPosition { index: 0, bits: 0 }, action)
    }

    pub(crate) fn new_branch(key: Box<[u8],A>, mask: u8) -> Node<T,N,K,A,H,M> {
        Node { key, kind: Kind::Branch(BranchData { mask, children: [const { None }; K] })}
    }

    pub(crate) fn new_leaf(key: Box<[u8],A>, value: T) -> Node<T,N,K,A,H,M> {
        Node { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }}
    }

    /// Sets a child on this node which must be a branch
    /// 
    /// SAFTEY: must ensure caller is a branch
    #[inline]
    unsafe fn raw_set_child(&mut self, idx: usize, node: Self, hash: Option<Output<H>>, alloc: A) -> Result<(), &'static str> {
        let hash = hash.unwrap_or(node.digest());
        let node = Box::new_in(node, alloc);
        match &mut self.kind {
            Kind::Branch(BranchData { children, .. }) => children[idx] = Some((hash, node)),
            // SAFETY: by assumption
            Kind::Leaf { .. } | Kind::Opaque(..) => unsafe { std::hint::unreachable_unchecked() },
        };
        Ok(())
    }
    
    /// returns number of bits in node key
    /// for a branch, this is all of the bits in the prefix, excluding all bits in its final byte that overlap/succeed the diff
    /// for a leaf, this is all of the bits in its key
    #[inline]
    fn get_key_bits(&self) -> usize {
        let mask_0s = match self.kind {
            Kind::Branch(BranchData{ mask, .. }) => mask.trailing_zeros(),
            Kind::Leaf { .. } | Kind::Opaque(..) => 8,
        };
        ((self.key.len()+1) * 8) - mask_0s as usize
    }

    pub fn num_children(&self) -> Option<usize> {
        match &self.kind {
            Kind::Branch(BranchData { children , .. }) => Some(children.len()),
            _ => None
        }
    }

    pub fn digest(&self) -> Output<H> {
        match &self.kind {
            Kind::Opaque(hash, _marker) => hash.clone(),
            Kind::Leaf { value, .. } => {
                let mut hasher = H::new();
                Digest::update(&mut hasher, &self.key);
                value.digest_update(&mut hasher);
                hasher.finalize()
            }
            Kind::Branch(BranchData { mask, children }) => {
                let mut hasher = H::new();
                Digest::update(&mut hasher, &self.key);
                Digest::update(&mut hasher, [*mask]);
                for child in children {
                    if let Some((hash, _)) = child {
                        Digest::update(&mut hasher, hash);
                    } else {
                        Digest::update(&mut hasher, empty_hash::<H>());
                    }
                }
                hasher.finalize()
            }
        }
    }

    fn debug_label(&self) -> String {
        match &self.kind {
            Kind::Leaf { .. } => format!("L({},*)", to_bin::<false>(&self.key)),
            Kind::Branch(BranchData { mask, children: _ }) => format!("B({},{},..)", to_bin::<false>(&self.key), to_bin::<false>(&[*mask])),
            Kind::Opaque(hash, _marker) => {
                let hash_prefix = &hash[0..std::cmp::min(hash.len(),4)];
                let hash_str = to_hex::<false>(hash_prefix);
                format!("O({})", hash_str)
            }
        }
    }
}

impl<T: Digestible + Debug, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Node<T,N,K,A,H,M> {
    pub(crate) fn debug_fmt(trie: &Option<(Output<H>, impl Borrow<Node<T,N,K,A,H,M>>)>, depth: usize, child_num: Option<usize>, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let space = " ".repeat(depth*2);
        write!(f, "{}", space)?;
        if let Some(child_num) = child_num {
            write!(f, "{:>3}: ", child_num)?;
        }
        if let Some((hash, node)) = trie {
            let hash_prefix = &hash[0..std::cmp::min(hash.len(),4)];
            let hash_str = to_hex::<false>(hash_prefix);
            let node = node.borrow();
            write!(f, "{} -> ", hash_str)?;
            match &node.kind {
                Kind::Leaf { value, .. } => {
                    write!(f, "L({}, {:?})", to_bin::<false>(&node.key), value)
                }
                Kind::Branch(BranchData { mask, children }) => {
                    write!(f, "B({}, {}, ", to_bin::<false>(&node.key), to_bin::<false>(&[*mask]))?;
                    for (idx, child) in children.iter().enumerate() {
                        write!(f, "\n")?;
                        Self::debug_fmt(&child, depth+1, Some(idx), f)?;
                    }
                    write!(f, "\n{})", space)
                }
                Kind::Opaque(_hash, _marker) => write!(f, "O({})", hash_str)
            }
        } else {
            if depth == 0 {
                write!(f, "Trie(Empty)")
            } else {
                write!(f, "E")
            }
        }
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Node<T,N,K,A,H,Complete> {
    pub fn to_partial(self) -> Node<T,N,K,A,H,Partial> {
        // SAFETY: Kind is #[repr(C, u8)] and Node/BranchData are #[repr(C)], and the
        // only field whose type varies with the mode (`Kind::Opaque`'s second field,
        // `M::Marker`) is a zero-sized tag, so it never affects the enum's size --
        // the `Output<H>` hash alongside it is identical in both modes. This makes
        // Concrete and Witness instantiations of Node layout-identical; asserted
        // below so any future change that breaks the invariant is a compile error,
        // not silent UB.
        //
        // `mem::transmute` can't be used directly: rustc's static size check can't
        // resolve `size_of` for the `key: Box<[u8], A>` field when `A` is a generic
        // `Allocator` type parameter (it bails out with "size can vary because of
        // A" even though A is identical on both sides). `transmute_copy` performs
        // the same bit-for-bit reinterpretation without that compile-time check, so
        // the `const` assertion below is what actually carries the safety proof.
        const {
            assert!(std::mem::size_of::<Self>() == std::mem::size_of::<Node<T,N,K,A,H,Partial>>());
            assert!(std::mem::align_of::<Self>() == std::mem::align_of::<Node<T,N,K,A,H,Partial>>());
        };
        let this = std::mem::ManuallyDrop::new(self);
        unsafe { std::mem::transmute_copy(&this) }
    }
}

// We need to build a frontier with a set of key fragments attached to it and gradually expand that frontier
impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> Node<T,N,K,A,H,Partial> {
    pub fn witness_for_keys(&mut self, mut keys: Vec<&[u8]>) {
        keys.sort();
        keys.dedup();
        let keys: Vec<_> = keys.into_iter().map(|k| (k, 0)).collect();
        let mut frontier = vec![(self, keys)];
        let mut per_node_keys= HashMap::new();
        let mut indices = Vec::with_capacity(K);

        // in this loop, we repeatedly prune nodes that are NOT in our frontier
        while frontier.len() != 0 {
            frontier = frontier.into_iter().flat_map(|(node, keys)| {
                // clear existing per-iteration structs
                per_node_keys.clear();
                indices.clear();

                // if this node is terminal, return immediately
                if node.num_children().is_none() {
                    return vec![];
                }

                // for each key, check whether that key can reach a particular child slot
                // by running find with a zero-bound (disabling recursion into child nodes)
                for (key, bits) in keys.into_iter() {
                    node.probe(Some(0), key, BitPosition { index: 0, bits }, |_, res| {
                        match res {
                            // this key reached a child slot, which means we must continue
                            // to check whether this key exists in the tree or not by computing
                            // a mapping from child slot -> key suffixes
                            ProbeResult::Bounded(p, _, slot) => {
                                let keys: &mut Vec<_> = per_node_keys.entry(slot).or_default();
                                keys.push((&key[p.index..], p.bits));
                            }
                            // in any other case, we have determined concuslively
                            // whether or not the key exists in the trie; no further
                            // work is required for this key
                            _ => {}
                        }
                    })
                };

                // SAFETY: we verified this node is a branch in the num_children check
                // we cannot move this above because this conflicts with the borrow from `node.find` above
                let children = match &mut node.kind {
                    Kind::Branch(BranchData { children , .. }) => children,
                    _ => unsafe { std::hint::unreachable_unchecked() },
                };

                // prune unreached children and collect reachable child indices in a vector
                for idx in 0..K {
                    if per_node_keys.contains_key(&idx) {
                        indices.push(idx);
                    } else {
                        if let Some(Some((hash, child))) = children.get_mut(idx) {
                            child.kind = Kind::Opaque(hash.clone(), ())
                        }
                    }
                }

                // SAFETY: all indices are disjoint and in-bounds by construction from our loop above
                // here, we grab unique mutable references to the reachable children of this node, which is valid due to disjointness
                let local_frontier: Vec<_> = unsafe { pick_mut_unchecked(children, &indices) };

                // finally, we expand the frontier vector for each child node
                indices.iter().zip(local_frontier.into_iter()).map(|(child_idx, node)| {
                    let node = &mut *node.as_mut().expect("Child node must exist for index").1;
                    let mut keys = per_node_keys.remove(&child_idx).expect("Cannot fail to locate existing index");
                    keys.sort();
                    keys.dedup();
                    (node, keys)
                }).collect()
            }).collect();
        }
    }

}

#[cfg(test)]
mod witness_tests {
    use allocator_api2::alloc::Global;
    use sha2::Sha256;
    use test_log::test;
    use crate::merkle::types::{Complete, Kind, Node, Trie};

    type U64BinaryTrie = Trie<u64,4,2,Global,Sha256,Complete>;

    #[test]
    fn initial_node_has_initial_key() {
        let mut t: U64BinaryTrie = Trie::new();
        let initial_key = &[1,2,3];
        t.set(initial_key, 42).unwrap();
        let (_hash, node) = t.1.unwrap();
        assert_eq!(&*node.key, initial_key);
    }

    // Regression test for `to_witness`'s transmute: a plain `cargo build` type-checks
    // the generic definition but never monomorphizes it (nothing in the crate calls
    // it), so a transmute that's unsound - or that simply fails to compile - for a
    // concrete instantiation can hide behind a green build. Instantiating it here
    // with a concrete allocator and hasher is what actually exercises the check.
    #[test]
    fn preserves_key_and_digest() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1,2,3,], 42).unwrap();
        let leaf: Node<u64, 4, 2, Global, Sha256, Complete> = Node {
            key: crate::utils::copy_slice_into_box(&[1, 2, 3], Global),
            kind: Kind::Leaf { value: 42u64, _phantom: std::marker::PhantomData },
        };
        let digest_before = leaf.digest();
        let key_before = leaf.key.to_vec();

        let witness = leaf.to_partial();

        assert_eq!(witness.key.to_vec(), key_before);
        assert_eq!(witness.digest(), digest_before);
    }

    #[test]
    fn witness_shape() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1,2,3,], 42).unwrap();
        println!("Orignal: {t:?}");
        t.set(&[1,2,4,], 43).unwrap();
        println!("Orignal: {t:?}");
        let mut t = t.to_partial();
        t.witness_for_keys(vec![&[1]]);
        println!("Witness: {t:?}");
    }
}