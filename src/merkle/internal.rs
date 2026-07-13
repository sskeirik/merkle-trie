/// Defines the Merkle Trie operations
use std::collections::HashMap;
use std::fmt::Debug;
use digest::{Digest, Output};
use crate::digestible::{Digestible, HashFrag, empty_hash};
use crate::merkle::types::{TrieMode, Node, NodeLink, NodeLinkRef, NodeUpdate, Kind};
use crate::merkle::types::mode::*;
use crate::utils::{Allocator, Box, NonNone, NonNoneMut, pick_mut_unchecked};
use crate::bitseqops::{BitDiff, BitPosition, BitSeqOps, find_first_distinct_bits};
#[allow(unused_imports)] // debugging or doc-comments
use {
    crate::merkle::types::Trie,
    tracing::{instrument, debug},
    crate::trace_val,
    crate::utils::{to_ascii, to_bin, to_hex},
};

/// Represents why a probe result terminated
pub(crate) enum ProbeResult<L,N> {
    /// An empty child slot corresponding to the probe key was found at N
    EmptySlot(L),
    /// An exact match for the probe key was found at N
    ExactMatch(N),
    /// A disagreement between the probe key and an existing node key was found at N
    Disagreement(N, BitDiff),
    /// An empty child slot corresponding to the probe key was found
    /// but could not be explored due to a depth bound due to the depth bound
    /// being reached
    Bounded(N, BitPosition, usize),
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> NodeLink<T,N,K,A,H,M> {

    /// Probes the trie, optionally with a bound, applying a user-specified action when the probe terminates
    #[instrument(level="debug", skip(self, bound, key, action))]
    pub(crate) fn probe<'a, R>(&'a self, mut bound: Option<usize>, key: &[u8], pos: BitPosition, action: impl FnOnce(BitPosition, ProbeResult<&'a Self, NonNone<'a,NodeLinkRef<T,N,K,A,H,M>>>) -> R) -> R {
        let label = if cfg!(debug_assertions) { self.debug_label() } else { const { String::new() } };

        let Some(opt_ref) = self.as_opt_ref() else {
            debug!("For {}, empty slot found at branch {}", to_ascii(key), label);
            return action(pos, ProbeResult::EmptySlot(self))
        };
        let (_hash, node) = opt_ref.get();

        let Some(split) = find_first_distinct_bits(&key[pos.index..], &node.key, pos.bits, None, Some(node.get_key_bits())) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(opt_ref))
        };

        match (&node.kind, split.prefix) {
            (Kind::Branch { children, .. }, Some(1)) => {
                let slot = split.mask_value::<K>(key);
                match bound {
                    Some(0) => {
                        debug!("For {}, search bound hit at node {}", to_ascii(key), label);
                        return action(pos, ProbeResult::Bounded(opt_ref, split.pos, slot))
                    }
                    Some(ref mut n) => *n -= 1,
                    _ => {}
                };
                children[slot].probe(bound, key, split.pos, action)
            },
            // no subtrie to explore, return
            _ => {
                debug!("For {}, disagreement {split:?} found at node {}", to_ascii(key), self.debug_label());
                action(pos, ProbeResult::Disagreement(opt_ref, split))
            }
        }
    }

    /// Probes the trie mutably, optionally with a bound, applying a user-specified action when the probe terminates that may modify the trie
    #[instrument(level="debug", skip(self, bound, key, action, alloc))]
    pub(crate) fn probe_mut<R>(&mut self, alloc: A, mut bound: Option<usize>, key: &[u8], pos: BitPosition, action: impl for <'a> FnOnce(BitPosition, ProbeResult<&'a mut Self, NonNoneMut<'a,NodeLinkRef<T,N,K,A,H,M>>>) -> R) -> R {
        let label = if cfg!(debug_assertions) { self.debug_label() } else { const { String::new() } };

        let Some(mut opt_mut) = self.as_opt_mut() else {
            debug!("For {}, empty slot found at branch {}", to_ascii(key), label);
            return action(pos, ProbeResult::EmptySlot(self))
        };
        let (hash, node) = opt_mut.as_mut();

        let Some(split) = find_first_distinct_bits(&key[pos.index..], &node.key, pos.bits, None, Some(node.get_key_bits())) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(opt_mut))
        };

        let (result, merge_data) = match (&mut node.kind, split.prefix) {
            (Kind::Branch { children, count, mask }, Some(1)) => {
                let slot = split.mask_value::<K>(key);
                match bound {
                    Some(0) => {
                        debug!("For {}, search bound hit at node {}", to_ascii(key), label);
                        return action(pos, ProbeResult::Bounded(opt_mut, split.pos, slot))
                    }
                    Some(ref mut n) => *n -= 1,
                    _ => {}
                };
                let child = &mut children[slot];
                // perform post-deletion cleanup, if necessary
                let pre_status = child.0.is_some();
                let result = child.probe_mut(alloc.clone(), bound, key, split.pos, action);
                let post_status = child.0.is_some();
                // is child count delta non-zero?
                let to_merge_child = if pre_status ^ post_status {
                    // apply delta
                    if pre_status {
                        *count -= 1
                    } else {
                        *count += 1
                    }
                    // if count is singleton, perform merge
                    if *count == 1 {
                        let mut child_data = None;
                        for (final_slot, link) in children.iter_mut().enumerate() {
                            if let Some((_hash, node)) = link.0.take() {
                                if child_data.is_some() {
                                    panic!("final node must be unique");
                                }
                                child_data = Some((final_slot, Box::into_inner(node)));
                                break;
                            }
                        }
                        let (final_slot, child) = child_data.expect("final node must exist");
                        Some((*mask, final_slot, child))
                    } else {
                        None
                    }
                } else {
                    None
                };
                (result, to_merge_child)
            },
            // no subtrie to explore, return
            _ => {
                debug!("For {}, disagreement {split:?} found at node {}", to_ascii(key), label);
                return action(pos, ProbeResult::Disagreement(opt_mut, split));
            }
        };
        // perform merge if needed
        if let Some((mask, slot, child)) = merge_data {
            // move child payload up, allocate new merged_key
            node.kind = child.kind;
            node.key = BitSeqOps::<K>::merge_prefix_mask_suffix(node.key.as_ref(), mask, slot as u8, child.key, alloc);
        }
        // fixup our hash if we have one
        *hash = node.digest();
        result
    }

    /// The internal implementation of [`Trie::update`] as a thin wrapper around `Self::probe_mut`.
    pub fn update<U: NodeUpdate<T>>(&mut self, target_key: &[u8], updater: U, alloc: A) -> Result<(), &'static str> {
        use ProbeResult::*;
        let alloc_copy = alloc.clone();
        let action = move |pos: BitPosition, find_result: ProbeResult<&mut Self, NonNoneMut<NodeLinkRef<T,N,K,A,H,M>>> | {
            match find_result {
                EmptySlot(link) => {
                    if let Some(value) = updater.on_vacant() {
                        let key = BitSeqOps::<K>::write_aligned_suffix::<A>(&pos, target_key, alloc.clone());
                        let leaf = Node::new_leaf(key, value);
                        link.0 = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
                        Ok(())
                    } else {
                        Err("Cannot create leaf with null initializer")
                    }
                }
                ExactMatch(link) => {
                    let (hash, node) = link.into_mut();
                    match &mut node.kind {
                        Kind::Leaf { value, .. } => updater.on_occupied(value),
                        _ => return Err("Unsupported trie set"),
                    };
                    *hash = node.digest();
                    Ok(())
                }
                Disagreement(existing, split) => {
                    let (existing_hash, existing_node) = existing.into_mut();
                    if split.prefix.is_some() {
                        return Err("Cannot set a value on a prefix");
                    }
                    let Some(new_value) = updater.on_vacant() else {
                        return Err("Cannot create leaf with null initializer")
                    };
                    // create keys/slots for to to-be-installed branch
                    let new_branch_key = split.write_prefix::<K,A>(&existing_node.key, alloc.clone());
                    let new_existing_key = split.write_suffix::<K,A>(&existing_node.key, alloc.clone());
                    let inserted_leaf_key = split.write_suffix::<K,A>(target_key, alloc.clone());
                    let new_existing_slot = split.mask_value::<K>(&existing_node.key);
                    let inserted_leaf_slot = split.mask_value::<K>(target_key);
                    // evict existing, install new branch
                    let new_branch = Node::new_branch(new_branch_key, split.mask::<K>());
                    let mut evicted = std::mem::replace(&mut **existing_node, new_branch);
                    let (installed_hash, installed_branch) = (existing_hash, existing_node);
                    // ready nodes for insertion
                    let inserted_leaf = Node::new_leaf(inserted_leaf_key, new_value);
                    evicted.key = new_existing_key;
                    unsafe {
                        installed_branch.raw_set_child(new_existing_slot, evicted, alloc.clone())?;
                        installed_branch.raw_set_child(inserted_leaf_slot, inserted_leaf, alloc.clone())?;
                    }
                    *installed_hash = installed_branch.digest();
                    Ok(())
                }
                Bounded(..) => unreachable!("Bound not set"),
            }
        };
        self.probe_mut(alloc_copy, None, target_key, BitPosition { index: 0, bits: 0 }, action)
    }

    pub fn delete(&mut self, target_key: &[u8], alloc: A) -> Option<T> {
        use ProbeResult::*;
        let action = |_: BitPosition, find_result: ProbeResult<&mut Self, NonNoneMut<NodeLinkRef<T,N,K,A,H,M>>> | {
            match find_result {
                ExactMatch(link) => {
                    match &link.as_ref().1.kind {
                        Kind::Leaf { .. } => {}
                        _ => return None,
                    };
                    let (_, leaf) = std::mem::take(link.into_inner()).expect("NonNone");
                    let leaf = Box::into_inner(leaf);
                    match leaf.kind {
                        Kind::Leaf { value, .. } => return Some(value),
                        _ => panic!("Kind::Leaf"),
                    }
                }
                _ => return None
            }
        };
        self.probe_mut(alloc, None, target_key, BitPosition { index: 0, bits: 0 }, action)
    }

    /// The internal implementation of [`Trie::get`] as a thin wrapper around `Self::probe`.
    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        use ProbeResult::*;
        let action = |_pos, result: ProbeResult<&'a Self, NonNone<'a, NodeLinkRef<T,N,K,A,H,M>>>| {
            match result {
                ExactMatch(ref link) => link.get().1.value(),
                _ => None,
            }
        };
        self.probe(None, search_key, BitPosition { index: 0, bits: 0 }, action)
    }

    /// Generates a short node label for debugging purposes
    fn debug_label(&self) -> String {
        let Some((hash, node)) = self.0.as_ref() else {
            return "Trie(Empty)".to_string()
        };
        match &node.kind {
            Kind::Leaf { .. } => format!("{} -> L({},*)", HashFrag::<H>(hash), to_bin::<false>(&node.key)),
            Kind::Branch { mask, count, children: _ } => format!("{} -> B({},{},{count} children)", HashFrag::<H>(hash), to_bin::<false>(&node.key), to_bin::<false>(&[*mask])),
            Kind::Opaque(..) => format!("{} -> O()", HashFrag::<H>(hash))
        }
    }

    pub(crate) fn stored_digest(&self) -> Output<H> {
        self.0.as_ref().map_or(empty_hash::<H>(), |(hash, _)| hash.clone())
    }

    fn deref(&self) -> Option<&(Output<H>, Box<Node<T,N,K,A,H,M>,A>)> {
        self.0.as_ref()
    }

    fn deref_mut(&mut self) -> Option<&mut(Output<H>, Box<Node<T,N,K,A,H,M>,A>)> {
        self.0.as_mut()
    }

    fn as_opt_ref(&self) -> Option<NonNone<'_, (Output<H>, Box<Node<T,N,K,A,H,M>, A>)>> {
        NonNone::new(&self.0)
    }

    fn as_opt_mut(&mut self) -> Option<NonNoneMut<'_, (Output<H>, Box<Node<T,N,K,A,H,M>, A>)>> {
        NonNoneMut::new(&mut self.0)
    }

    fn is_empty(&self) -> bool {
        self.0.is_none()
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> Node<T,N,K,A,H,M> {
    /// Constructs a new branch node for this trie
    pub(crate) fn new_branch(key: Box<[u8],A>, mask: u8) -> Self {
        Self { key, kind: Kind::Branch { mask, count: 0, children: [const { NodeLink(None) }; K] }}
    }

    /// Constructs a new leaf node for this trie
    pub(crate) fn new_leaf(key: Box<[u8],A>, value: T) -> Self {
        Self { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }}
    }

    /// Upserts a child node into the current node at the given slot.
    /// 
    /// SAFTEY: must ensure caller node has [`Kind::Branch`].
    #[inline]
    unsafe fn raw_set_child(&mut self, idx: usize, node: Self, alloc: A) -> Result<(), &'static str> {
        let link = NodeLink(Some((node.digest(), Box::new_in(node, alloc))));
        match &mut self.kind {
            Kind::Branch { children, count, .. } => {
                let child_slot = &mut children[idx];
                let was_empty = child_slot.is_empty();
                *child_slot = link;
                if was_empty { 
                    *count += 1; 
                }
            }
            // SAFETY: by assumption
            Kind::Leaf { .. } | Kind::Opaque(..) => unsafe { std::hint::unreachable_unchecked() },
        };
        Ok(())
    }
    
    /// Return the number of bits which participate in key comparisons against this node.
    /// 
    /// For [`Kind::Branch`] or [`Kind::Opaque`] nodes, this is just all bits in the key.
    /// For [`Kind::Branch`] nodes, perform the same calculation but subtract all bits in the final byte that overlap/succeed the mask.
    #[inline]
    fn get_key_bits(&self) -> usize {
        let extra_bits = match self.kind {
            Kind::Branch { mask, .. } => 8 - mask.trailing_zeros(),
            Kind::Leaf { .. } | Kind::Opaque(..) => 0
        };
        self.key.len()*8 - extra_bits as usize
    }

    pub fn value(&self) -> Option<&T> {
        match &self.kind {
            Kind::Leaf { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Returns the number of children stored under this node
    pub fn is_terminal(&self) -> bool {
        matches!(self.kind, Kind::Branch { .. })
    }

    /// The internal implementation of [`Trie::digest`] that only requires examining the local node.
    pub fn digest(&self) -> Output<H> {
        match &self.kind {
            Kind::Opaque(hash, _marker) => hash.clone(),
            Kind::Leaf { value, .. } => {
                let mut hasher = H::new();
                Digest::update(&mut hasher, &self.key);
                value.digest_update(&mut hasher);
                hasher.finalize()
            }
            // NOTE: the count field does not contribute to the digest since
            // it is just a read-only view over the children field
            Kind::Branch { mask, children, count: _ } => {
                let mut hasher = H::new();
                Digest::update(&mut hasher, &self.key);
                Digest::update(&mut hasher, [*mask]);
                for child in children {
                    Digest::update(&mut hasher, child.stored_digest())
                }
                hasher.finalize()
            }
        }
    }
}


impl<T: Digestible + Debug, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> NodeLink<T,N,K,A,H,M> {
    /// This function drives the [`Debug`] implementation for [`Trie`].
    pub(crate) fn debug_fmt(&self, depth: usize, child_num: Option<usize>, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let space = " ".repeat(depth*2);
        write!(f, "{}", space)?;
        if let Some(child_num) = child_num {
            write!(f, "{:>3}: ", child_num)?;
        }
        if let Some((hash, node)) = self.0.as_ref() {
            write!(f, "{} -> ", HashFrag::<H>(hash))?;
            match &node.kind {
                Kind::Leaf { value, .. } => {
                    write!(f, "L({}, {:?})", to_bin::<false>(&node.key), value)
                }
                Kind::Branch { mask, children, .. } => {
                    write!(f, "B({}, {}, ", to_bin::<false>(&node.key), to_bin::<false>(&[*mask]))?;
                    for (idx, child) in children.iter().enumerate() {
                        write!(f, "\n")?;
                        Self::debug_fmt(&child, depth+1, Some(idx), f)?;
                    }
                    write!(f, "\n{})", space)
                }
                Kind::Opaque(..) => write!(f, "O({})", HashFrag::<H>(hash))
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
    /// The internal implementation of [`Trie::to_partial`]
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

    /// Boxed variant of [`Self::to_partial`], reinterpreting `Box<Self,A>` in place without
    /// unboxing/reboxing so the allocation is reused as-is.
    pub fn to_partial_boxed(this: Box<Self,A>) -> Box<Node<T,N,K,A,H,Partial>,A> {
        // SAFETY: see `to_partial` -- Self and Node<T,N,K,A,H,Partial> are layout-identical,
        // so the pointee behind the box may be reinterpreted; the allocator is threaded
        // through unchanged so the box can later be freed in the same allocator it came from.
        const {
            assert!(std::mem::size_of::<Self>() == std::mem::size_of::<Node<T,N,K,A,H,Partial>>());
            assert!(std::mem::align_of::<Self>() == std::mem::align_of::<Node<T,N,K,A,H,Partial>>());
        };
        let (raw, alloc) = Box::into_raw_with_allocator(this);
        unsafe { Box::from_raw_in(raw as *mut Node<T,N,K,A,H,Partial>, alloc) }
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> NodeLink<T,N,K,A,H,Partial> {
    /// The internal implementation of [`Trie::witness_for_keys`]
    pub fn witness_for_keys(&mut self, mut keys: Vec<&[u8]>) {
        keys.sort();
        keys.dedup();
        let keys: Vec<_> = keys.into_iter().map(|k| (k, 0)).collect();
        let mut frontier = vec![(self, keys)];
        let mut per_node_keys= HashMap::new();
        let mut indices = Vec::with_capacity(K);

        // in this loop, we repeatedly prune nodes that are NOT in our frontier
        while frontier.len() != 0 {
            frontier = frontier.into_iter().flat_map(|(link, keys)| {
                // if the node doesn't exist or else is terminal, the current keys
                // cannot be used to expand the frontier further, so stop exploration
                let NodeLink(Some((_, node))) = &link else {
                    return vec![];
                };
                if node.is_terminal() {
                    return vec![];
                }

                // clear structs for this iteration
                per_node_keys.clear();
                indices.clear();

                // for each key, check whether that key can reach a particular child slot
                // by running find with a zero-bound (disabling recursion into child nodes)
                for (key, bits) in keys.into_iter() {
                    link.probe(Some(0), key, BitPosition { index: 0, bits }, |_, res| {
                        match res {
                            // this key reached a child slot, which means we must continue
                            // to check whether this key exists in the tree or not by computing
                            // a mapping from child slot -> key suffixes
                            ProbeResult::Bounded(_, pos, slot) => {
                                let keys: &mut Vec<_> = per_node_keys.entry(slot).or_default();
                                keys.push((&key[pos.index..], pos.bits));
                            }
                            // in any other case, we have determined concuslively
                            // whether or not the key exists in the trie; no further
                            // work is required for this key
                            _ => {}
                        }
                    })
                };

                let (_, node) = link.deref_mut().expect("internal error: already checked option");
                // SAFETY: we verified this node is a branch in the num_children check
                // we cannot move this above because this conflicts with the borrow from `node.find` above
                let children = match &mut node.kind {
                    Kind::Branch { children , .. } => children,
                    _ => unsafe { std::hint::unreachable_unchecked() },
                };

                // prune unreached children and collect reachable child indices in a vector
                for idx in 0..K {
                    if per_node_keys.contains_key(&idx) {
                        indices.push(idx);
                    } else {
                        if let Some(NodeLink(Some((hash, child)))) = children.get_mut(idx) {
                            child.kind = Kind::Opaque(hash.clone(), ())
                        }
                    }
                }

                // SAFETY: all indices are disjoint and in-bounds by construction from our loop above
                // here, we grab unique mutable references to the reachable children of this node, which is valid due to disjointness
                let local_frontier: Vec<_> = unsafe { pick_mut_unchecked(children, &indices) };

                // finally, we expand the frontier vector for each child node
                indices.iter().zip(local_frontier.into_iter()).map(|(child_idx, node)| {
                    // let node = &mut *node.as_mut().expect("Child node must exist for index").1;
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
        println!("Orig: {t:?}");
        t.set(initial_key, 42).unwrap();
        println!("Set: {t:?}");
        let (_hash, node) = t.1.0.unwrap();
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
    fn test_delete() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1,2,3,], 42).unwrap();
        let orig = t.clone();
        println!("With 42: {t:?}");
        t.set(&[1,2,4,], 43).unwrap();
        println!("With 43: {t:?}");
        t.delete(&[1,2,4]).unwrap();
        assert!(orig.weak_eq(&t), "Original and Deleted tries are unequal:\n{orig:?}\n{t:?}");
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