//! Internal Merkle [`Trie`] node representation and algorithms.

use std::fmt::Debug;
use std::collections::HashMap;
use digest::{Digest, Output};
use crate::digestible::{Digestible, HashFrag, empty_hash};
use crate::trie::{TrieError, NodeUpdate};
use crate::utils::{Allocator, Box, NonNone, NonNoneMut, pick_unchecked, pick_mut_unchecked};
use crate::bitseqops::{BitDiff, BitPosition, BitSeqOps, find_first_distinct_bits};
#[allow(unused_imports)] // debugging or doc-comments
use {
    tracing::{instrument, debug},
    crate::utils::{to_ascii, to_bin, to_hex},
    crate::trie::Trie,
};

/// A node in a Merkleized, compressed trie.
///
/// The `repr(C)` attribute ensures a consistent representation across the distinct [`TrieMode`]s
 #[repr(C)]
pub(super) struct Node<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode> {
    /// the whole bytes that must be matched to visit this node
    pub key: Box<[u8],A>,
    /// the node's kind-specific data
    pub kind: Kind<T,N,K,H,A,M>,
}

impl<T: Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone, H:Digest, M: TrieMode> Clone for Node<T,N,K,H,A,M> {
    fn clone(&self) -> Self {
        Self {
            key: self.key.clone(),
            kind: self.kind.clone(),
        } 
    }
}

/// A generic Merkle trie node payload
///
/// The `repr(C,u8)` attribute ensures a consistent representation across the distinct [`TrieMode`]s
#[repr(C, u8)]
pub(super) enum Kind<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode> {
    /// A trie branch
    Branch {
        /// Encodes the log2(`K`) bits in the [`Node::key`]`.len()`th byte that distinguishes the keys of child nodes
        mask: u8,
        /// Stores the `K` child nodes of this branch
        children: [NodeLink<T,N,K,H,A,M>; K],
    },
    /// A trie leaf
    Leaf {
        /// the data stored at this leaf
        value: T,
        /// zero-sized type that exists to record the hash algorithm used by this trie
        _phantom: std::marker::PhantomData<H>,
    },
    /// Witness for a subtrie of unknown shape (only constructible if [`TrieMode`] is set to [`Partial`]).
    Opaque(Output<H>, M::Marker),
}

impl<T: Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone, H:Digest, M: TrieMode> Clone for Kind<T,N,K,H,A,M> {
    fn clone(&self) -> Self {
        use Kind::*;
        match self {
            Opaque(h, m) => Opaque(h.clone(), m.clone()),
            Leaf { value , _phantom } => Leaf { value: value.clone(), _phantom: *_phantom },
            Branch { mask, children } => {
                Branch { mask: *mask, children: children.clone() }
            }
        }
    }
}

/// The hash reference contained inside a [`NodeLink`]
pub(super) type NodeLinkInner<T,const N: usize, const K: usize, H, A, M> = (Output<H>, Box<Node<T,N,K,H,A,M>, A>);

/// A nullable link between [`Node`]s in a [`Trie`]
pub(super) struct NodeLink<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>(
    pub Option<NodeLinkInner<T,N,K,H,A,M>>,
);

impl<T: Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone, H:Digest, M: TrieMode> Clone for NodeLink<T,N,K,H,A,M> {
    fn clone(&self) -> Self {
        match &self.0 {
            None => Self(None),
            Some((h, node)) => Self(Some((h.clone(), node.clone())))
        }
    }
}

// Opaque [`Trie`] Node Tag Type.
mod sealed { pub trait SealedTrieMode {} }
pub use mode::{Complete, Partial};
pub mod mode {
    #[allow(unused_imports)] // for doc-comments
    use super::Kind;
    #[allow(unused_imports)] // for doc-comments
    use crate::trie::Trie;
    /// Marker type that forces a [`Trie`] to be complete (i.e., it _cannot_ contain opaque nodes).
    #[derive(Clone)]
    pub struct Complete;
    /// Marker type that permits a [`Trie`] to be partial (i.e., it _may_ contain opaque nodes).
    #[derive(Clone)]
    pub struct Partial;
    impl super::sealed::SealedTrieMode for Complete {}
    impl super::sealed::SealedTrieMode for Partial {}
    impl super::TrieMode for Complete {
        type Marker = std::convert::Infallible;
    }
    impl super::TrieMode for Partial {
        type Marker = ();
    }
}

/// Trait that describes whether a [`Trie`] may be partial
/// (i.e., may contain opaque nodes).
pub trait TrieMode: sealed::SealedTrieMode {
    /// ZST tag stored in opaque nodes.
    /// In [`Complete`] tries, resolves to the empty type
    /// (preventing construction of opaque nodes).
    type Marker: Clone;
}

/// A probe result to be handled by a probe action
enum ProbeResult<L,N> {
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

impl<T: Digestible, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> NodeLink<T,N,K,H,A,M> {
    /// Probe the trie, optionally with a bound, applying a user-specified action when the probe terminates
    #[instrument(level="debug", skip(self, bound, key, action))]
    fn probe<'a, R>(&'a self, mut bound: Option<usize>, key: &[u8], pos: BitPosition, action: impl FnOnce(BitPosition, ProbeResult<(), NonNone<'a,NodeLinkInner<T,N,K,H,A,M>>>) -> R) -> R {
        let label = if cfg!(debug_assertions) { self.debug_label() } else { const { String::new() } };

        let Some(opt_ref) = self.as_opt_ref() else {
            debug!("For {}, empty slot found at branch {}", to_ascii(key), label);
            return action(pos, ProbeResult::EmptySlot(()))
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
                let next_pos = split.pos.increment::<K>();
                debug!("Recursing into {slot} with pos {:?}", next_pos);
                children[slot].probe(bound, key, next_pos, action)
            },
            // no subtrie to explore, return
            _ => {
                debug!("For {}, disagreement {split:?} found at node {}", to_ascii(key), self.debug_label());
                action(pos, ProbeResult::Disagreement(opt_ref, split))
            }
        }
    }

    /// Probe the trie mutably, optionally with a bound, applying a user-specified action when the probe terminates that may modify the trie
    #[instrument(level="debug", skip(self, bound, key, action, alloc))]
    fn probe_mut<R>(&mut self, alloc: A, mut bound: Option<usize>, key: &[u8], pos: BitPosition, action: impl for <'a> FnOnce(BitPosition, ProbeResult<&'a mut Self, NonNoneMut<'a,NodeLinkInner<T,N,K,H,A,M>>>) -> R) -> R {
        let label = if cfg!(debug_assertions) { self.debug_label() } else { const { String::new() } };

        let Some(mut opt_mut) = self.as_opt_mut() else {
            debug!("For {}, empty slot found at branch {}", to_ascii(key), label);
            return action(pos, ProbeResult::EmptySlot(self))
        };
        let (hash, node) = opt_mut.reborrow_mut();

        let Some(split) = find_first_distinct_bits(&key[pos.index..], &node.key, pos.bits, None, Some(node.get_key_bits())) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(opt_mut))
        };

        let (result, merge_data) = match (&mut node.kind, split.prefix) {
            (Kind::Branch { children, mask }, Some(1)) => {
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
                let next_pos = split.pos.increment::<K>();
                debug!("Recursing into {slot} with pos {:?}", next_pos);
                // perform post-deletion cleanup, if necessary
                let pre_full = child.0.is_some();
                let result = child.probe_mut(alloc.clone(), bound, key, next_pos, action);
                let post_empty = child.0.is_none();
                // TODO: Consider implementation options that add a branch size counter and only
                //       perform this linear scan when the branch size counter hits zero.
                //       This is not currently done not because it can't be made to work but
                //       because I didn't find an implementation style that I liked.
                let to_merge_child = if pre_full & post_empty {
                    // if one child remains, perform merge
                    let mut child_data = None;
                    for (final_slot, link) in children.iter_mut().enumerate() {
                        if let Some((_hash, node)) = link.0.take() {
                            if child_data.is_some() {
                                break;
                            }
                            child_data = Some((final_slot, Box::into_inner(node)));
                        }
                    }
                    child_data.map(|(final_slot, child)| (*mask, final_slot, child))
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
            node.key = BitSeqOps::<K>::recover(node.key.as_ref(), mask, slot as u8, child.key, alloc);
        }
        // fixup our hash if we have one
        *hash = node.digest();
        result
    }

    /// Implement [`Trie::update`] as a thin wrapper around `Self::probe_mut`.
    pub(super) fn update<U: NodeUpdate<T>>(&mut self, target_key: &[u8], updater: U, alloc: A) -> Result<(), TrieError> {
        use ProbeResult::*;
        let alloc_copy = alloc.clone();
        let action = move |pos: BitPosition, find_result: ProbeResult<&mut Self, NonNoneMut<NodeLinkInner<T,N,K,H,A,M>>> | {
            match find_result {
                EmptySlot(link) => {
                    if let Some(value) = updater.on_vacant() {
                        let key = BitSeqOps::<K>::write_aligned_suffix::<A>(&pos, target_key, alloc.clone());
                        let leaf = Node::new_leaf(key, value);
                        link.0 = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
                        Ok(())
                    } else {
                        Err(TrieError::MissingInitializer)
                    }
                }
                ExactMatch(link) => {
                    let (hash, node) = link.into_mut();
                    match &mut node.kind {
                        Kind::Leaf { value, .. } => updater.on_occupied(value),
                        _ => return Err(TrieError::UnsupportedSet),
                    };
                    *hash = node.digest();
                    Ok(())
                }
                Disagreement(existing, split) => {
                    let (existing_hash, existing_node) = existing.into_mut();
                    if split.prefix.is_some() {
                        return Err(TrieError::SetOnPrefix);
                    }
                    let Some(new_value) = updater.on_vacant() else {
                        return Err(TrieError::MissingInitializer)
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

    /// Implement [`Trie::delete`] as a thin wrapper around `Self::probe_mut`.
    pub(super) fn delete(&mut self, target_key: &[u8], alloc: A) -> Option<T> {
        use ProbeResult::*;
        let action = |_: BitPosition, find_result: ProbeResult<&mut Self, NonNoneMut<NodeLinkInner<T,N,K,H,A,M>>> | {
            match find_result {
                ExactMatch(link) => {
                    match &link.reborrow_ref().1.kind {
                        Kind::Leaf { .. } => {}
                        _ => return None,
                    };
                    let (_, leaf) = std::mem::take(link.into_inner()).expect("NonNone");
                    let leaf = Box::into_inner(leaf);
                    match leaf.kind {
                        Kind::Leaf { value, .. } => Some(value),
                        _ => panic!("Kind::Leaf"),
                    }
                }
                _ => None
            }
        };
        self.probe_mut(alloc, None, target_key, BitPosition { index: 0, bits: 0 }, action)
    }

    /// Implement [`Trie::get`] as a thin wrapper around `Self::probe`.
    pub(super) fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        use ProbeResult::*;
        let action = |_pos, result: ProbeResult<(), NonNone<'a, NodeLinkInner<T,N,K,H,A,M>>>| {
            match result {
                ExactMatch(ref link) => link.get().1.value_ref(),
                _ => None,
            }
        };
        self.probe(None, search_key, BitPosition { index: 0, bits: 0 }, action)
    }

    /// Return the digest stored at this [`NodeLink`]
    pub(super) fn stored_digest(&self) -> Output<H> {
        self.0.as_ref().map_or(empty_hash::<H>(), |(hash, _)| hash.clone())
    }

    /// Return a reference to this [`NodeLink`]'s payload as optional `NonNone` option reference
    fn as_opt_ref(&self) -> Option<NonNone<'_, NodeLinkInner<T,N,K,H,A,M>>> {
        NonNone::new(&self.0)
    }

    /// Return a reference to this [`NodeLink`]'s payload as optional `NonNoneMut` option reference
    fn as_opt_mut(&mut self) -> Option<NonNoneMut<'_, NodeLinkInner<T,N,K,H,A,M>>> {
        NonNoneMut::new(&mut self.0)
    }

    /// Return whether this link is terminal
    fn is_terminal(&self) -> bool {
        self.0.as_ref().is_none_or(|(_, node)| node.is_terminal())
    }

    /// Generate a short node label for debugging purposes
    fn debug_label(&self) -> String {
        let Some((hash, node)) = self.0.as_ref() else {
            return "Trie(Empty)".to_string()
        };
        match &node.kind {
            Kind::Leaf { .. } => format!("{} -> L({},*)", HashFrag::<H>(hash), to_bin::<false>(&node.key)),
            Kind::Branch { mask, children: _ } => format!("{} -> B({},{},..)", HashFrag::<H>(hash), to_bin::<false>(&node.key), to_bin::<false>(&[*mask])),
            Kind::Opaque(..) => format!("{} -> O()", HashFrag::<H>(hash))
        }
    }
}

impl<T: Digestible, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> Node<T,N,K,H,A,M> {
    /// Construct a new branch node for this trie
    pub(super) fn new_branch(key: Box<[u8],A>, mask: u8) -> Self {
        Self { key, kind: Kind::Branch { mask, children: [const { NodeLink(None) }; K] }}
    }

    /// Construct a new leaf node for this trie
    pub(super) fn new_leaf(key: Box<[u8],A>, value: T) -> Self {
        Self { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }}
    }

    /// Returns a reference to this node's children
    /// 
    /// SAFETY: must ensure caller node has [`Kind::Branch`]
    pub(crate) unsafe fn as_children(&self) -> &[NodeLink<T,N,K,H,A,M>; K] {
        match &self.kind {
            Kind::Branch { children, .. } => children,
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    /// Returns a mutable reference to this node's children
    /// 
    /// SAFETY: must ensure caller node has [`Kind::Branch`]
    pub(crate) unsafe fn as_children_mut(&mut self) -> &mut [NodeLink<T,N,K,H,A,M>; K] {
        match &mut self.kind {
            Kind::Branch { children, .. } => children,
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    /// Implement [`Trie::digest`] in a way that only requires examining the local node.
    pub(super) fn digest(&self) -> Output<H> {
        match &self.kind {
            Kind::Opaque(hash, _marker) => hash.clone(),
            Kind::Leaf { value, .. } => {
                let mut hasher = H::new();
                Digest::update(&mut hasher, &self.key);
                value.update_hasher(&mut hasher);
                hasher.finalize()
            }
            Kind::Branch { mask, children } => {
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

    /// Upsert a child node into the current node at the given slot.
    ///
    /// SAFTEY: must ensure caller node has [`Kind::Branch`].
    #[inline]
    unsafe fn raw_set_child(&mut self, idx: usize, node: Self, alloc: A) -> Result<(), TrieError> {
        let link = NodeLink(Some((node.digest(), Box::new_in(node, alloc))));
        match &mut self.kind {
            Kind::Branch { children, .. } => children[idx] = link,
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

    /// Return a reference to the value
    fn value_ref(&self) -> Option<&T> {
        match &self.kind {
            Kind::Leaf { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Return the number of children stored under this node
    fn is_terminal(&self) -> bool {
        matches!(self.kind, Kind::Branch { .. })
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> NodeLink<T,N,K,H,A,Complete> {
    /// Reinterpret a [`NodeLink`] in-place
    pub(super) fn into_partial(self) -> NodeLink<T,N,K,H,A,Partial> {
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
        // SAFETY: see `to_partial` -- Self and Node<T,N,K,H,A,Partial> are layout-identical,
        // so the pointee behind the box may be reinterpreted; the allocator is threaded
        // through unchanged so the box can later be freed in the same allocator it came from.
        const {
            assert!(std::mem::size_of::<Self>() == std::mem::size_of::<NodeLink<T,N,K,H,A,Partial>>());
            assert!(std::mem::align_of::<Self>() == std::mem::align_of::<NodeLink<T,N,K,H,A,Partial>>());
        };
        if let NodeLink(Some((digest, complete_node))) = self {
            let (raw, alloc) = Box::into_raw_with_allocator(complete_node);
            let partial_node = unsafe { Box::from_raw_in(raw as *mut Node<T,N,K,H,A,Partial>, alloc) };
            NodeLink(Some((digest, partial_node)))
        } else {
            NodeLink(None)
        }
    }
}

/// Trait that can aids in walking trie structure using a per-level frontier.
pub(super) trait TrieFrontierCursor<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone>: Sized {
    /// Returns a reference to the current trie node we are visiting
    fn source(&self) -> &NodeLink<T,N,K,H,A,Partial>;
    /// Performs some in-place mutation of a child of the node we are currently visiting
    /// 
    /// # SAFETY
    /// 
    /// The visited node must have [`Kind::Branch`] and `index`
    /// must be a valid child node index for the node.
    unsafe fn process_child(&mut self, idx: usize, found: bool);
    /// Splits the currently visited node into a vector of child nodes
    /// 
    /// # SAFETY
    /// 
    /// The visited node must have [`Kind::Branch`] and the indices
    /// must correspond to non-`None` child nodes.
    unsafe fn into_children(self, indices: &[usize]) -> Vec<Self>;
}

/// Given a set of keys, build a minimal witness for the given
/// keys by walking over the trie structure, level-by-level,
/// using a [`TrieFrontierCursor`].
#[allow(clippy::single_match)]
pub(super) fn to_witness_for_keys_generic<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone>(context: impl TrieFrontierCursor<T,N,K,H,A>, mut keys: Vec<&[u8]>) {
    keys.sort();
    keys.dedup();
    let keys: Vec<_> = keys.into_iter().map(|k| (k, 0)).collect();
    let mut frontier = vec![(context, keys)];
    let mut per_node_keys= HashMap::new();
    let mut indices = Vec::with_capacity(K);

    // in this loop, we repeatedly prune nodes that are NOT in our frontier
    while !frontier.is_empty() {
        frontier = frontier.into_iter().flat_map(|(mut context, keys)| {
            let link: &NodeLink<T,N,K,H,A,Partial> = context.source();
            // if the node doesn't exist or else is terminal, the current keys
            // cannot be used to expand the frontier further, so stop exploration
            if link.is_terminal() {
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
                        // in any other case, we have determined conclusively
                        // whether or not the key exists in the trie; no further
                        // work is required for this key
                        _ => {}
                    }
                })
            };

            // prune unreached children and collect reachable child indices in a vector
            for idx in 0..K {
                let found = per_node_keys.contains_key(&idx);
                if found {
                    indices.push(idx);
                }
                unsafe { context.process_child(idx, found) };
            }

            // SAFETY: all indices are disjoint and in-bounds by construction from our loop above
            // here, we grab unique mutable references to the reachable children of this node, which is valid due to disjointness
            let local_frontier: Vec<_> = unsafe { context.into_children(&indices) };

            // finally, we expand the frontier vector for each child node
            indices.iter().zip(local_frontier).map(|(child_idx, node)| {
                let mut keys = per_node_keys.remove(child_idx).expect("Cannot fail to locate existing index");
                keys.sort();
                keys.dedup();
                (node, keys)
            }).collect()
        }).collect();
    }
}

/// A view of partial trie used to construct a witness in-place.
impl<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone> TrieFrontierCursor<T,N,K,H,A> for &mut NodeLink<T,N,K,H,A,Partial> {
    fn source(&self) -> &NodeLink<T,N,K,H,A,Partial> {
        self
    }

    unsafe fn process_child(&mut self, idx: usize, found: bool) {
        if !found {
            let children = unsafe { self.0.as_mut().expect("checked is branch").1.as_children_mut() };
            if let Some(NodeLink(Some((hash, child)))) = children.get_mut(idx) {
                child.kind = Kind::Opaque(hash.clone(), ())
            }
        }
    }

    unsafe fn into_children(self, indices: &[usize]) -> Vec<Self>
    {
        let children = unsafe { self.0.as_mut().expect("checked is branch").1.as_children_mut() };
        unsafe { pick_mut_unchecked( &mut children[..], indices) }
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> NodeLink<T,N,K,H,A,Partial> {
    /// Implement [`Trie::witness_for_keys`] via visiting every node reachable
    /// by a key in `keys` and then pruning all nodes that are not reachable in this manner
    pub(super) fn prune_for_keys(&mut self, keys: Vec<&[u8]>) {
        to_witness_for_keys_generic(self, keys);
    }
}

/// A view of [`Complete`] Trie node paired with a [`Partial`] clone of itself
/// that is used to build a witness from a Trie by only cloning their shared super-Trie
struct WitnessBuilder<'src, 'tgt, T: Digestible + Clone, const N: usize, const K: usize, H: Digest, A: Allocator + Clone>(
    &'src NodeLink<T,N,K,H,A,Complete>,
    &'tgt mut NodeLink<T,N,K,H,A,Partial>,
    A
);

impl<'src, 'tgt, T: Digestible + Clone, const N: usize, const K: usize, H: Digest, A: Allocator + Clone> TrieFrontierCursor<T,N,K,H,A> for WitnessBuilder<'src,'tgt,T,N,K,H,A> {
    fn source(&self) -> &NodeLink<T,N,K,H,A,Partial> {
        unsafe { std::mem::transmute(&self.0) } 
    }

    unsafe fn process_child(&mut self, idx: usize, found: bool) {
        let src_children = unsafe { self.0.0.as_ref().unwrap_unchecked().1.as_children() };
        let tgt_children = unsafe { self.1.0.as_mut().unwrap_unchecked().1.as_children_mut() };
        if found {
            tgt_children[idx] = src_children[idx].clone_as_leaf();
        } else {
            if let Some(NodeLink(Some((hash, child)))) = src_children.get(idx) {
                let node = Node { key: child.key.clone(), kind: Kind::Opaque(hash.clone(),()) };
                tgt_children[idx] = NodeLink(Some((hash.clone(), Box::new_in(node, self.2.clone()))));
            }
        }
    }

    unsafe fn into_children(self, indices: &[usize]) -> Vec<Self> {
        let src_children = unsafe { self.0.0.as_ref().unwrap_unchecked().1.as_children() };
        let tgt_children = unsafe { self.1.0.as_mut().unwrap_unchecked().1.as_children_mut() };

        let sel_src_children: Vec<_> = unsafe { pick_unchecked(src_children, indices) };
        let sel_tgt_children: Vec<_> = unsafe { pick_mut_unchecked(tgt_children, indices) };

        sel_src_children.into_iter().zip(sel_tgt_children).map(|(src,tgt)| Self(src,tgt,self.2.clone())).collect()
    }
}

impl<T: Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> NodeLink<T,N,K,H,A,Complete> {
    /// The internal implementation of [`Trie::witness_for_keys`]
    pub fn to_witness_for_keys(&self, keys: Vec<&[u8]>, alloc: A) -> NodeLink<T,N,K,H,A,Partial> {
        let mut new_root = self.clone_as_leaf();
        let builder = WitnessBuilder(self, &mut new_root, alloc);
        to_witness_for_keys_generic(builder, keys);
        new_root
    }

    fn clone_as_leaf(&self) -> NodeLink<T,N,K,H,A,Partial> {
        use Kind::*;
        let NodeLink(Some((hash, node))) = self else {
            return NodeLink(None)
        };
        let node: Box<Node<T,N,K,H,A,Complete>, A> = match node.kind {
            Leaf { .. } => node.clone(),
            Branch { mask, .. } => {
                let key_copy = node.key.clone();
                let node_copy = Node::new_branch(key_copy, mask);
                Box::new_in(node_copy, Box::allocator(node).clone())
            }
            Opaque(_, tag) => match tag {},
        };
        NodeLink(Some((hash.clone(), node))).into_partial()
    }
}

 /// Node equality is just equality of its node structure.
 impl<T: Digestible + PartialEq + Eq, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> PartialEq for NodeLink<T,N,K,H,A,M> {
     fn eq(&self, other: &Self) -> bool {
         use Kind::*;
         match (&self.0, &other.0) {
             (Some((_, node1)), Some((_, node2))) => {
                 node1.key == node2.key && match (&node1.kind, &node2.kind) {
                     (Leaf { value: v1, ..  }, Leaf { value: v2, .. }) => v1 == v2,
                     (Opaque(digest1, _), Opaque(digest2, _)) => digest1 == digest2,
                     (Branch { mask: m1, children: c1 }, Branch { mask: m2, children: c2 }) => {
                         m1 == m2 && c1.iter().zip(c2.iter()).all(|(c1, c2)| c1 == c2 )
                     }
                     (_, _) => false,
                 }
             }
             (None, None) => true,
             _ => false,
         }
     }
 }

 /// The debug format of a node is a nested presentation of the trie structure
 impl<T: Digestible + Debug, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> Debug for NodeLink<T,N,K,H,A,M> {
     fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
         self.debug_fmt( 0, None, f)
     }
 }

impl<T: Digestible + Debug, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> NodeLink<T,N,K,H,A,M> {
    /// This function drives the [`Debug`] implementation for [`Trie`].
    pub(super) fn debug_fmt(&self, depth: usize, child_num: Option<usize>, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                        writeln!(f)?;
                        Self::debug_fmt(child, depth+1, Some(idx), f)?;
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

#[cfg(test)]
mod witness_tests {
    use allocator_api2::alloc::Global;
    use sha2::Sha256;
    use test_log::test;
    use crate::{Trie, Complete, Digest, Digestible};
    use crate::digestible::{empty_hash, W};

    type U64BinaryTrie = Trie<W<u64>,4,2,Sha256,Global,Complete>;

    #[test]
    fn initial_node_has_initial_key() {
        let mut t: U64BinaryTrie = Trie::new();
        let initial_key = &[1,2,3];
        println!("Orig: {t:?}");
        t.set(initial_key, W(42)).unwrap();
        println!("Set: {t:?}");
        let (_hash, node) = t.1.0.unwrap();
        assert_eq!(&*node.key, initial_key);
    }

    #[test]
    fn preserves_key_and_digest() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1,2,3,], W(42)).unwrap();
        let digest_before = t.digest();
        let witness = t.clone().to_partial();
        assert_eq!(witness.digest(), digest_before);
        assert_eq!(t.get(&[1,2,3]), witness.get(&[1,2,3]));
    }

    #[test]
    fn test_delete() {
        let mut t: U64BinaryTrie = Trie::new();
        println!("Empty: {t:?}");
        t.set(&[1,2,3,], W(42)).unwrap();
        let orig = t.clone();
        println!("With 42: {t:?}");
        t.set(&[1,2,4,], W(43)).unwrap();
        println!("With 43: {t:?}");
        t.delete(&[1,2,4]).unwrap();
        assert!(orig.hash_eq(&t), "Original and Deleted tries are unequal:\n{orig:?}\n{t:?}");
        println!("With 42: {t:?}");
        t.delete(&[1,2,3]).unwrap();
        assert_eq!(t.digest(), empty_hash::<Sha256>());
        println!("Final: {t:?}");
    }

    #[test]
    fn witness_shape() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1,2,3,], W(42)).unwrap();
        println!("Orignal: {t:?}");
        t.set(&[1,2,4,], W(43)).unwrap();
        println!("Orignal: {t:?}");
        let mut t = t.to_partial();
        t.prune_for_keys(vec![&[1]]);
        println!("Witness: {t:?}");
    }

    #[derive(Clone, Debug)]
    struct MyCustomData(u64);
    impl Digestible for MyCustomData {
        fn update_hasher<D: Digest>(&self, hasher: &mut D) {
            hasher.update(&self.0.to_le_bytes())
        }
    }

    type MyTrie = Trie<MyCustomData,4,2,Sha256,Global,Complete>;

    #[test]
    fn misc_test() {
        let mut t: MyTrie = Trie::new();
        t.set(&[1,2,3], MyCustomData(45)).expect("trie set error");
        t.set(&[1,2,5], MyCustomData(127)).expect("trie set error");
        println!("Original trie: {t:?}");
        t.set(&[1,2,4], MyCustomData(78)).expect("trie set error");
        let delete_result = t.delete(&[1,2,4]);
        match delete_result {
           Ok(v) => println!("Old value at key was {v:?}"),
           Err(e) => println!("Error {e} occurred"),
        };
        println!("\n\n\nAfter delete trie: {t:?}\n\n\n");
        let get_result = t.get(&[1,2,3]);
        match get_result {
           Ok(v) => println!("Borrow a value: {v:?}"),
           Err(e) => println!("Error {e} occurred"),
        }

        // // if Trie data supports Clone/Debug, so does Trie
        // let trie_clone = t.clone();
        // println!("Trie clone: {trie_clone:?}");

        // // build witnesses
        // let mut witness1 = t.clone().to_partial();
        // witness1.witness_for_keys(vec![&[1,2]]);
        // println!("Witness 1: {witness1:?}");

        // let mut witness2 = t.clone().to_partial();
        // witness2.witness_for_keys(vec![&[1,2,3]]);
        // println!("Witness 2: {witness2:?}");
    }
}
