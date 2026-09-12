//! Internal Merkle [`Trie`] node representation and algorithms.

use crate::bitseqops::{BitDiff, BitPosition, BitSeqOps, find_first_distinct_bits};
use crate::digestible::{Digestible, HashFrag, HashWitnessValue, empty_hash};
use crate::trie::{NodeUpdate, TrieError};
use crate::utils::{Allocator, Box, NonNone, NonNoneMut, pick_mut_unchecked, pick_unchecked};
use digest::{Digest, Output};
use std::collections::HashMap;
use std::fmt::Debug;
use std::marker::PhantomData;
#[allow(unused_imports)] // debugging or doc-comments
use {
    crate::trie::Trie,
    crate::utils::{to_ascii, to_bin, to_hex},
    tracing::{debug, instrument},
};

/// A node in a Merkleized, compressed trie.
///
/// The `repr(C)` attribute ensures a consistent representation across the distinct [`TrieMode`]s
#[repr(C)]
pub(super) struct Node<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> {
    /// the whole bytes that must be matched to visit this node
    pub key: Box<[u8], A>,
    /// the node's kind-specific data
    pub kind: Kind<T, N, K, H, A, M>,
}

impl<
    T: Digestible + Clone,
    const N: usize,
    const K: usize,
    A: Allocator + Clone,
    H: Digest,
    M: TrieMode,
> Clone for Node<T, N, K, H, A, M>
{
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
pub(super) enum Kind<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> {
    /// A trie branch
    Branch {
        /// Encodes the log2(`K`) bits in the [`Node::key`]`.len()`th byte that distinguishes the keys of child nodes
        mask: u8,
        /// Stores the `K` child nodes of this branch
        children: [NodeLink<T, N, K, H, A, M>; K],
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

impl<
    T: Digestible + Clone,
    const N: usize,
    const K: usize,
    A: Allocator + Clone,
    H: Digest,
    M: TrieMode,
> Clone for Kind<T, N, K, H, A, M>
{
    fn clone(&self) -> Self {
        use Kind::*;
        match self {
            Opaque(h, m) => Opaque(h.clone(), m.clone()),
            Leaf { value, _phantom } => Leaf {
                value: value.clone(),
                _phantom: *_phantom,
            },
            Branch { mask, children } => Branch {
                mask: *mask,
                children: children.clone(),
            },
        }
    }
}

/// The hash reference contained inside a [`NodeLink`]
pub(super) type NodeLinkInner<T, const N: usize, const K: usize, H, A, M> =
    (Output<H>, Box<Node<T, N, K, H, A, M>, A>);

/// A nullable link between [`Node`]s in a [`Trie`]
pub(super) struct NodeLink<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
>(pub Option<NodeLinkInner<T, N, K, H, A, M>>);

impl<
    T: Digestible + Clone,
    const N: usize,
    const K: usize,
    A: Allocator + Clone,
    H: Digest,
    M: TrieMode,
> Clone for NodeLink<T, N, K, H, A, M>
{
    fn clone(&self) -> Self {
        match &self.0 {
            None => Self(None),
            Some((h, node)) => Self(Some((h.clone(), node.clone()))),
        }
    }
}

// Opaque [`Trie`] Node Tag Type.
mod sealed {
    pub trait SealedTrieMode {}
}
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
#[derive(Debug)]
enum ProbeResult<L, N> {
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

impl<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>
    NodeLink<T, N, K, H, A, M>
{
    /// Probe the trie, optionally with a bound, applying a user-specified action when the probe terminates
    #[instrument(level = "debug", skip(self, bound, key, action))]
    fn probe<'a, R>(
        &'a self,
        mut bound: Option<usize>,
        key: &[u8],
        pos: BitPosition,
        action: impl FnOnce(
            BitPosition,
            ProbeResult<(), NonNone<'a, NodeLinkInner<T, N, K, H, A, M>>>,
        ) -> R,
    ) -> R {
        let label = if cfg!(debug_assertions) {
            self.debug_label()
        } else {
            const { String::new() }
        };

        let Some(opt_ref) = self.as_opt_ref() else {
            debug!(
                "For {}, empty slot found at branch {}",
                to_ascii(key),
                label
            );
            return action(pos, ProbeResult::EmptySlot(()));
        };
        let (_hash, node) = opt_ref.get();

        let Some(split) = find_first_distinct_bits(
            &key[pos.index..],
            &node.key,
            pos.bits,
            None,
            Some(node.get_key_bits().saturating_sub(pos.bits)),
        ) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(opt_ref));
        };

        match (&node.kind, split.prefix) {
            (Kind::Branch { children, .. }, Some(1)) => {
                // `split.pos` is relative to `&key[pos.index..]`; make it absolute
                // (relative to `key` itself) before using it against the full key.
                let global_pos = BitPosition {
                    index: pos.index + split.pos.index,
                    bits: split.pos.bits,
                };
                let slot = BitSeqOps::<K>::mask_value(key, global_pos.index, global_pos.bits);
                match bound {
                    Some(0) => {
                        debug!("For {}, search bound hit at node {}", to_ascii(key), label);
                        return action(pos, ProbeResult::Bounded(opt_ref, global_pos.increment::<K>(), slot));
                    }
                    Some(ref mut n) => *n -= 1,
                    _ => {}
                };
                let next_pos = global_pos.increment::<K>();
                debug!("Recursing into {slot} with pos {:?}", next_pos);
                children[slot].probe(bound, key, next_pos, action)
            }
            // no subtrie to explore, return
            _ => {
                debug!(
                    "For {}, disagreement {split:?} found at node {}",
                    to_ascii(key),
                    self.debug_label()
                );
                action(pos, ProbeResult::Disagreement(opt_ref, split))
            }
        }
    }

    /// Probe the trie mutably, optionally with a bound, applying a user-specified action when the probe terminates that may modify the trie
    #[instrument(level = "debug", skip(self, bound, key, action, alloc))]
    fn probe_mut<R>(
        &mut self,
        alloc: A,
        mut bound: Option<usize>,
        key: &[u8],
        pos: BitPosition,
        action: impl for<'a> FnOnce(
            BitPosition,
            ProbeResult<&'a mut Self, NonNoneMut<'a, NodeLinkInner<T, N, K, H, A, M>>>,
        ) -> R,
    ) -> R {
        let label = if cfg!(debug_assertions) {
            self.debug_label()
        } else {
            const { String::new() }
        };

        let Some(mut opt_mut) = self.as_opt_mut() else {
            debug!(
                "For {}, empty slot found at branch {}",
                to_ascii(key),
                label
            );
            return action(pos, ProbeResult::EmptySlot(self));
        };
        let (hash, node) = opt_mut.reborrow_mut();

        let Some(split) = find_first_distinct_bits(
            &key[pos.index..],
            &node.key,
            pos.bits,
            None,
            Some(node.get_key_bits().saturating_sub(pos.bits)),
        ) else {
            debug!("For {}, exact match found at node {}", to_ascii(key), label);
            return action(pos, ProbeResult::ExactMatch(opt_mut));
        };

        let (result, merge_data) = match (&mut node.kind, split.prefix) {
            (Kind::Branch { children, mask }, Some(1)) => {
                // `split.pos` is relative to `&key[pos.index..]`; make it absolute
                // (relative to `key` itself) before using it against the full key.
                let global_pos = BitPosition {
                    index: pos.index + split.pos.index,
                    bits: split.pos.bits,
                };
                let slot = BitSeqOps::<K>::mask_value(key, global_pos.index, global_pos.bits);
                match bound {
                    Some(0) => {
                        debug!("For {}, search bound hit at node {}", to_ascii(key), label);
                        return action(pos, ProbeResult::Bounded(opt_mut, global_pos.increment::<K>(), slot));
                    }
                    Some(ref mut n) => *n -= 1,
                    _ => {}
                };
                let child = &mut children[slot];
                let next_pos = global_pos.increment::<K>();
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
            }
            // no subtrie to explore, return
            _ => {
                debug!(
                    "For {}, disagreement {split:?} found at node {}",
                    to_ascii(key),
                    label
                );
                return action(pos, ProbeResult::Disagreement(opt_mut, split));
            }
        };
        // perform merge if needed
        if let Some((mask, slot, child)) = merge_data {
            // move child payload up, allocate new merged_key
            node.kind = child.kind;
            node.key =
                BitSeqOps::<K>::recover(node.key.as_ref(), mask, slot as u8, child.key, alloc);
        }
        // fixup our hash if we have one
        *hash = node.digest();
        result
    }

    /// Implement [`Trie::update`] as a thin wrapper around `Self::probe_mut`.
    pub(super) fn update<U: NodeUpdate<T>>(
        &mut self,
        target_key: &[u8],
        updater: U,
        alloc: A,
    ) -> Result<(), TrieError> {
        use ProbeResult::*;
        let alloc_copy = alloc.clone();
        let action = move |pos: BitPosition,
                           find_result: ProbeResult<
            &mut Self,
            NonNoneMut<NodeLinkInner<T, N, K, H, A, M>>,
        >| {
            match find_result {
                EmptySlot(link) => {
                    if let Some(value) = updater.on_vacant() {
                        let key = BitSeqOps::<K>::write_aligned_suffix::<A>(
                            &pos,
                            target_key,
                            alloc.clone(),
                        );
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
                        return Err(TrieError::MissingInitializer);
                    };
                    // create keys/slots for to to-be-installed branch
                    let new_branch_key =
                        split.write_prefix::<K, A>(&existing_node.key, alloc.clone());
                    let new_existing_key =
                        split.write_suffix::<K, A>(&existing_node.key, alloc.clone());
                    // `split.pos` is relative to `&target_key[pos.index..]` (the slice
                    // that was actually compared against `existing_node.key`), so the
                    // same slice (not the full `target_key`!) must be used here.
                    let inserted_leaf_key =
                        split.write_suffix::<K, A>(&target_key[pos.index..], alloc.clone());
                    let new_existing_slot = split.mask_value::<K>(&existing_node.key);
                    let inserted_leaf_slot = split.mask_value::<K>(&target_key[pos.index..]);
                    // evict existing, install new branch
                    let new_branch = Node::new_branch(new_branch_key, split.mask::<K>());
                    let mut evicted = std::mem::replace(&mut **existing_node, new_branch);
                    let (installed_hash, installed_branch) = (existing_hash, existing_node);
                    // ready nodes for insertion
                    let inserted_leaf = Node::new_leaf(inserted_leaf_key, new_value);
                    evicted.key = new_existing_key;
                    unsafe {
                        installed_branch.raw_set_child(
                            new_existing_slot,
                            evicted,
                            alloc.clone(),
                        )?;
                        installed_branch.raw_set_child(
                            inserted_leaf_slot,
                            inserted_leaf,
                            alloc.clone(),
                        )?;
                    }
                    *installed_hash = installed_branch.digest();
                    Ok(())
                }
                Bounded(..) => unreachable!("Bound not set"),
            }
        };
        self.probe_mut(
            alloc_copy,
            None,
            target_key,
            BitPosition { index: 0, bits: 0 },
            action,
        )
    }

    /// Implement [`Trie::delete`] as a thin wrapper around `Self::probe_mut`.
    pub(super) fn delete(&mut self, target_key: &[u8], alloc: A) -> Option<T> {
        use ProbeResult::*;
        let action = |_: BitPosition,
                      find_result: ProbeResult<
            &mut Self,
            NonNoneMut<NodeLinkInner<T, N, K, H, A, M>>,
        >| {
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
                _ => None,
            }
        };
        self.probe_mut(
            alloc,
            None,
            target_key,
            BitPosition { index: 0, bits: 0 },
            action,
        )
    }

    /// Implement [`Trie::get`] as a thin wrapper around `Self::probe`.
    pub(super) fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        use ProbeResult::*;
        let action =
            |_pos, result: ProbeResult<(), NonNone<'a, NodeLinkInner<T, N, K, H, A, M>>>| {
                match result {
                    ExactMatch(ref link) => link.get().1.value_ref(),
                    _ => None,
                }
            };
        self.probe(None, search_key, BitPosition { index: 0, bits: 0 }, action)
    }

    /// Given a search key, return:
    /// `None` - if the key's presence in the trie is unknowable (due to opaque nodes),
    /// `Some(true)` - if the key is in the trie,
    /// `Some(false)` - if the key is NOT in the trie.
    pub(super) fn verify<'a>(&'a self, search_key: &[u8]) -> Option<bool> {
        use ProbeResult::*;
        let action =
            |_pos, result: ProbeResult<(), NonNone<'a, NodeLinkInner<T, N, K, H, A, M>>>| {
                match result {
                    ExactMatch(node) => {
                        if matches!(node.get().1.kind, Kind::Opaque(..)) {
                            None
                        } else {
                            Some(true)
                        }
                    }
                    EmptySlot(..) => {
                        Some(false)
                    }
                    // if disagreement is such that we could continue exploration
                    // from an opaque, give up; otherwise, we found a true negative
                    Disagreement(node, diff) => {
                        if diff.prefix == Some(1) && matches!(node.get().1.kind, Kind::Opaque(..)) {
                            None
                        } else {
                            Some(false)
                        }
                    }
                    Bounded(..) => panic!("unreachable because no bound specified"),
                }
            };
        self.probe(None, search_key, BitPosition { index: 0, bits: 0 }, action)
    }

    /// Return the digest stored at this [`NodeLink`]
    pub(super) fn stored_digest(&self) -> Output<H> {
        self.0
            .as_ref()
            .map_or(empty_hash::<H>(), |(hash, _)| hash.clone())
    }

    /// Return a reference to this [`NodeLink`]'s payload as optional `NonNone` option reference
    fn as_opt_ref(&self) -> Option<NonNone<'_, NodeLinkInner<T, N, K, H, A, M>>> {
        NonNone::new(&self.0)
    }

    /// Return a reference to this [`NodeLink`]'s payload as optional `NonNoneMut` option reference
    fn as_opt_mut(&mut self) -> Option<NonNoneMut<'_, NodeLinkInner<T, N, K, H, A, M>>> {
        NonNoneMut::new(&mut self.0)
    }

    /// Return whether this link is terminal
    fn is_terminal(&self) -> bool {
        self.0.as_ref().is_none_or(|(_, node)| node.is_terminal())
    }

    /// Generate a short node label for debugging purposes
    fn debug_label(&self) -> String {
        let Some((hash, node)) = self.0.as_ref() else {
            return "Trie(Empty)".to_string();
        };
        match &node.kind {
            Kind::Leaf { .. } => format!(
                "{} -> L({},*)",
                HashFrag::<H>(hash),
                to_bin::<false>(&node.key)
            ),
            Kind::Branch { mask, children: _ } => format!(
                "{} -> B({},{},..)",
                HashFrag::<H>(hash),
                to_bin::<false>(&node.key),
                to_bin::<false>(&[*mask])
            ),
            Kind::Opaque(..) => format!("{} -> O()", HashFrag::<H>(hash)),
        }
    }
}

impl<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>
    Node<T, N, K, H, A, M>
{
    /// Construct a new branch node for this trie
    pub(super) fn new_branch(key: Box<[u8], A>, mask: u8) -> Self {
        Self {
            key,
            kind: Kind::Branch {
                mask,
                children: [const { NodeLink(None) }; K],
            },
        }
    }

    /// Construct a new leaf node for this trie
    pub(super) fn new_leaf(key: Box<[u8], A>, value: T) -> Self {
        Self {
            key,
            kind: Kind::Leaf {
                value,
                _phantom: std::marker::PhantomData,
            },
        }
    }

    /// Returns a reference to this node's children
    ///
    /// SAFETY: must ensure caller node has [`Kind::Branch`]
    pub(crate) unsafe fn as_children(&self) -> &[NodeLink<T, N, K, H, A, M>; K] {
        match &self.kind {
            Kind::Branch { children, .. } => children,
            _ => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    /// Returns a mutable reference to this node's children
    ///
    /// SAFETY: must ensure caller node has [`Kind::Branch`]
    pub(crate) unsafe fn as_children_mut(&mut self) -> &mut [NodeLink<T, N, K, H, A, M>; K] {
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
            Kind::Leaf { .. } | Kind::Opaque(..) => 0,
        };
        self.key.len() * 8 - extra_bits as usize
    }

    /// Return a reference to the value
    fn value_ref(&self) -> Option<&T> {
        match &self.kind {
            Kind::Leaf { value, .. } => Some(value),
            _ => None,
        }
    }

    /// Return whether this node is terminal (i.e., has no children to recurse into)
    fn is_terminal(&self) -> bool {
        !matches!(self.kind, Kind::Branch { .. })
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    NodeLink<T, N, K, H, A, Complete>
{
    /// Reinterpret a [`NodeLink`] in-place
    pub(super) fn into_partial(self) -> NodeLink<T, N, K, H, A, Partial> {
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
            assert!(
                std::mem::size_of::<Self>()
                    == std::mem::size_of::<NodeLink<T, N, K, H, A, Partial>>()
            );
            assert!(
                std::mem::align_of::<Self>()
                    == std::mem::align_of::<NodeLink<T, N, K, H, A, Partial>>()
            );
        };
        if let NodeLink(Some((digest, complete_node))) = self {
            let (raw, alloc) = Box::into_raw_with_allocator(complete_node);
            let partial_node =
                unsafe { Box::from_raw_in(raw as *mut Node<T, N, K, H, A, Partial>, alloc) };
            NodeLink(Some((digest, partial_node)))
        } else {
            NodeLink(None)
        }
    }
}

/// Trait that can aids in walking trie structure using a per-level frontier.
pub(super) trait TrieFrontierCursor<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
>: Sized
{
    /// Returns a reference to the current trie node we are visiting
    fn source(&self) -> &NodeLink<T, N, K, H, A, Partial>;
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
pub(super) fn to_witness_for_keys_generic<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
>(
    context: impl TrieFrontierCursor<T, N, K, H, A>,
    mut keys: Vec<&[u8]>,
) {
    keys.sort();
    keys.dedup();
    let keys: Vec<_> = keys.into_iter().map(|k| (k, 0)).collect();
    let mut frontier = vec![(context, keys)];
    let mut per_node_keys = HashMap::new();
    let mut indices = Vec::with_capacity(K);

    // in this loop, we repeatedly prune nodes that are NOT in our frontier
    while !frontier.is_empty() {
        frontier = frontier
            .into_iter()
            .flat_map(|(mut context, keys)| {
                let link: &NodeLink<T, N, K, H, A, Partial> = context.source();
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
                }

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
                indices
                    .iter()
                    .zip(local_frontier)
                    .map(|(child_idx, node)| {
                        let mut keys = per_node_keys
                            .remove(child_idx)
                            .expect("Cannot fail to locate existing index");
                        keys.sort();
                        keys.dedup();
                        (node, keys)
                    })
                    .collect()
            })
            .collect();
    }
}

/// A view of partial trie used to construct a witness in-place.
impl<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone>
    TrieFrontierCursor<T, N, K, H, A> for &mut NodeLink<T, N, K, H, A, Partial>
{
    fn source(&self) -> &NodeLink<T, N, K, H, A, Partial> {
        self
    }

    unsafe fn process_child(&mut self, idx: usize, found: bool) {
        if !found {
            let children = unsafe {
                self.0
                    .as_mut()
                    .expect("checked is branch")
                    .1
                    .as_children_mut()
            };
            if let Some(NodeLink(Some((hash, child)))) = children.get_mut(idx) {
                child.kind = Kind::Opaque(hash.clone(), ())
            }
        }
    }

    unsafe fn into_children(self, indices: &[usize]) -> Vec<Self> {
        let children = unsafe {
            self.0
                .as_mut()
                .expect("checked is branch")
                .1
                .as_children_mut()
        };
        unsafe { pick_mut_unchecked(&mut children[..], indices) }
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    NodeLink<T, N, K, H, A, Partial>
{
    /// Implement [`Trie::witness_for_keys`] via visiting every node reachable
    /// by a key in `keys` and then pruning all nodes that are not reachable in this manner
    pub(super) fn prune_for_keys(&mut self, keys: Vec<&[u8]>) {
        to_witness_for_keys_generic(self, keys);
    }
}

/// A view of [`Complete`] Trie node paired with a [`Partial`] clone of itself
/// that is used to build a witness from a Trie by only cloning their shared super-Trie
struct WitnessBuilder<
    'src,
    'tgt,
    T: Digestible + Clone,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
>(
    &'src NodeLink<T, N, K, H, A, Complete>,
    &'tgt mut NodeLink<T, N, K, H, A, Partial>,
    A,
);

impl<
    'src,
    'tgt,
    T: Digestible + Clone,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
> TrieFrontierCursor<T, N, K, H, A> for WitnessBuilder<'src, 'tgt, T, N, K, H, A>
{
    fn source(&self) -> &NodeLink<T, N, K, H, A, Partial> {
        // SAFETY: NodeLink<..., Complete> and NodeLink<..., Partial> are
        // layout-identical, but note that self.0 is _already_ a ref;
        // if we attempt transmute &self.0, we are reinterpreting a
        // ref-to-ref as a ref, which obviously is wrong. The fact
        // that Rust does silently converts between ref'ed types in
        // other contexts makes this requirement slightly less obvious
        unsafe { std::mem::transmute(self.0) }
    }

    unsafe fn process_child(&mut self, idx: usize, found: bool) {
        let src_children = unsafe { self.0.0.as_ref().unwrap_unchecked().1.as_children() };
        let tgt_children = unsafe { self.1.0.as_mut().unwrap_unchecked().1.as_children_mut() };
        if found {
            tgt_children[idx] = src_children[idx].clone_as_leaf();
        } else {
            if let Some(NodeLink(Some((hash, child)))) = src_children.get(idx) {
                let node = Node {
                    key: child.key.clone(),
                    kind: Kind::Opaque(hash.clone(), ()),
                };
                tgt_children[idx] =
                    NodeLink(Some((hash.clone(), Box::new_in(node, self.2.clone()))));
            }
        }
    }

    unsafe fn into_children(self, indices: &[usize]) -> Vec<Self> {
        let src_children = unsafe { self.0.0.as_ref().unwrap_unchecked().1.as_children() };
        let tgt_children = unsafe { self.1.0.as_mut().unwrap_unchecked().1.as_children_mut() };

        let sel_src_children: Vec<_> = unsafe { pick_unchecked(src_children, indices) };
        let sel_tgt_children: Vec<_> = unsafe { pick_mut_unchecked(tgt_children, indices) };

        sel_src_children
            .into_iter()
            .zip(sel_tgt_children)
            .map(|(src, tgt)| Self(src, tgt, self.2.clone()))
            .collect()
    }
}

impl<T: Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone, H: Digest>
    NodeLink<T, N, K, H, A, Complete>
{
    /// The internal implementation of [`Trie::to_witness_for_keys`]
    pub fn to_witness_for_keys(
        &self,
        keys: Vec<&[u8]>,
        alloc: A,
    ) -> NodeLink<T, N, K, H, A, Partial> {
        let mut new_root = self.clone_as_leaf();
        let builder = WitnessBuilder(self, &mut new_root, alloc);
        to_witness_for_keys_generic(builder, keys);
        new_root
    }

    fn clone_as_leaf(&self) -> NodeLink<T, N, K, H, A, Partial> {
        use Kind::*;
        let NodeLink(Some((hash, node))) = self else {
            return NodeLink(None);
        };
        let node: Box<Node<T, N, K, H, A, Complete>, A> = match node.kind {
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

/// A view of [`Complete`] Trie node paired with a [`Partial`] clone of itself
/// where trie values are represented by their hashes; can build an approximate
/// witness from a non-[`Clone`]able Trie by representing to-be-cloned values
/// by their digest
struct HashWitnessBuilder<
    'src,
    'tgt,
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
>(
    &'src NodeLink<T, N, K, H, A, Complete>,
    &'tgt mut NodeLink<HashWitnessValue<H>, N, K, H, A, Partial>,
    A,
);

impl<
    'src,
    'tgt,
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
> TrieFrontierCursor<T, N, K, H, A> for HashWitnessBuilder<'src, 'tgt, T, N, K, H, A>
{
    fn source(&self) -> &NodeLink<T, N, K, H, A, Partial> {
        // SAFETY: NodeLink<..., Complete> and NodeLink<..., Partial> are
        // layout-identical (see the SAFETY comment on `NodeLink::into_partial`),
        // so a `&NodeLink<Complete>` may be reinterpreted as `&NodeLink<Partial>`
        // for read-only access.
        unsafe { std::mem::transmute(self.0) }
    }

    unsafe fn process_child(&mut self, idx: usize, found: bool) {
        let src_children = unsafe { self.0.0.as_ref().unwrap_unchecked().1.as_children() };
        let tgt_children = unsafe { self.1.0.as_mut().unwrap_unchecked().1.as_children_mut() };
        if found {
            tgt_children[idx] = src_children[idx].clone_as_hash_leaf();
        } else {
            if let Some(NodeLink(Some((hash, child)))) = src_children.get(idx) {
                let node = Node {
                    key: child.key.clone(),
                    kind: Kind::Opaque(hash.clone(), ()),
                };
                tgt_children[idx] =
                    NodeLink(Some((hash.clone(), Box::new_in(node, self.2.clone()))));
            }
        }
    }

    unsafe fn into_children(self, indices: &[usize]) -> Vec<Self> {
        let src_children = unsafe { self.0.0.as_ref().unwrap_unchecked().1.as_children() };
        let tgt_children = unsafe { self.1.0.as_mut().unwrap_unchecked().1.as_children_mut() };

        let sel_src_children: Vec<_> = unsafe { pick_unchecked(src_children, indices) };
        let sel_tgt_children: Vec<_> = unsafe { pick_mut_unchecked(tgt_children, indices) };

        sel_src_children
            .into_iter()
            .zip(sel_tgt_children)
            .map(|(src, tgt)| Self(src, tgt, self.2.clone()))
            .collect()
    }
}

impl<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest> NodeLink<T, N, K, H, A, Complete>
{
    /// The internal implementation of [`Trie::to_hash_witness_for_keys`]
    pub fn to_hash_witness_for_keys(
        &self,
        keys: Vec<&[u8]>,
        alloc: A,
    ) -> NodeLink<HashWitnessValue<H>, N, K, H, A, Partial> {
        let mut new_root = self.clone_as_hash_leaf();
        let builder = HashWitnessBuilder(self, &mut new_root, alloc);
        to_witness_for_keys_generic(builder, keys);
        new_root
    }

    fn clone_as_hash_leaf(&self) -> NodeLink<HashWitnessValue<H>, N, K, H, A, Partial> {
        use Kind::*;
        let NodeLink(Some((hash, node))) = self else {
            return NodeLink(None);
        };
        let kind: Kind<HashWitnessValue<H>, N, K, H, A, Complete> = match node.kind {
            Leaf { .. } => Leaf { value: HashWitnessValue(node.digest()), _phantom: PhantomData },
            Branch { mask, .. } => Branch { mask, children: [const { NodeLink(None) }; K] },
            Opaque(_, tag) => match tag {},
        };
        let node_copy = Node { key: node.key.clone(), kind };
        let node: Box<Node<HashWitnessValue<H>, N, K, H, A, Complete>, A> =
            Box::new_in(node_copy, Box::allocator(node).clone());
        NodeLink(Some((hash.clone(), node))).into_partial()
    }
}

/// Node equality is just equality of its node structure.
impl<
    T: Digestible + PartialEq + Eq,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> PartialEq for NodeLink<T, N, K, H, A, M>
{
    fn eq(&self, other: &Self) -> bool {
        use Kind::*;
        match (&self.0, &other.0) {
            (Some((_, node1)), Some((_, node2))) => {
                node1.key == node2.key
                    && match (&node1.kind, &node2.kind) {
                        (Leaf { value: v1, .. }, Leaf { value: v2, .. }) => v1 == v2,
                        (Opaque(digest1, _), Opaque(digest2, _)) => digest1 == digest2,
                        (
                            Branch {
                                mask: m1,
                                children: c1,
                            },
                            Branch {
                                mask: m2,
                                children: c2,
                            },
                        ) => m1 == m2 && c1.iter().zip(c2.iter()).all(|(c1, c2)| c1 == c2),
                        (_, _) => false,
                    }
            }
            (None, None) => true,
            _ => false,
        }
    }
}

/// The debug format of a node is a nested presentation of the trie structure
impl<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> Debug for NodeLink<T, N, K, H, A, M>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(0, None, f)
    }
}

impl<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> Debug for Node<T, N, K, H, A, M>
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.debug_fmt(0, f)
    }
}

impl<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> NodeLink<T, N, K, H, A, M>
{
    /// This function drives the [`Debug`] implementation for [`Trie`]. Leaf values are
    /// always elided as `..`; see [`Self::debug_fmt_verbose`] to print them when `T: Debug`.
    pub(super) fn debug_fmt(
        &self,
        depth: usize,
        child_num: Option<usize>,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        self.debug_fmt_impl(depth, child_num, f, &|_, f| write!(f, ".."))
    }

    /// Shared implementation behind [`Self::debug_fmt`] and [`Self::debug_fmt_verbose`].
    ///
    /// `T` is not required to be [`Debug`] here: how a leaf's value is printed is
    /// entirely decided by the caller-supplied `value_fmt`, which is where the `T:
    /// Debug` bound (when needed) actually lives. This sidesteps the fact that Rust
    /// cannot directly write trait bounds generic over whether `T: Debug` holds.
    fn debug_fmt_impl(
        &self,
        depth: usize,
        child_num: Option<usize>,
        f: &mut std::fmt::Formatter<'_>,
        value_fmt: &dyn Fn(&T, &mut std::fmt::Formatter<'_>) -> std::fmt::Result,
    ) -> std::fmt::Result {
        let space = " ".repeat(depth * 2);
        write!(f, "{}", space)?;
        if let Some(child_num) = child_num {
            write!(f, "{:>3}: ", child_num)?;
        }
        if let Some((hash, node)) = self.0.as_ref() {
            write!(f, "{} -> ", HashFrag::<H>(hash))?;
            Node::debug_fmt_impl(node, depth, f, value_fmt)
        } else {
            if depth == 0 {
                write!(f, "Trie(Empty)")
            } else {
                write!(f, "E")
            }
        }
    }
}

impl<
    T: Digestible + Debug,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> NodeLink<T, N, K, H, A, M>
{
    /// Like [`Self::debug_fmt`], but prints each leaf's actual value via `T`'s
    /// [`Debug`] impl instead of eliding it. Drives [`Trie::debug_with_values`].
    pub(super) fn debug_fmt_verbose(
        &self,
        depth: usize,
        child_num: Option<usize>,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        self.debug_fmt_impl(depth, child_num, f, &|value, f| write!(f, "{:?}", value))
    }
}

impl<
    T: Digestible,
    const N: usize,
    const K: usize,
    H: Digest,
    A: Allocator + Clone,
    M: TrieMode,
> Node<T, N, K, H, A, M> {
    /// See [`NodeLink::debug_fmt`].
    pub(super) fn debug_fmt(
        &self,
        depth: usize,
        f: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        self.debug_fmt_impl(depth, f, &|_, f| write!(f, ".."))
    }

    /// See [`NodeLink::debug_fmt_impl`].
    fn debug_fmt_impl(
        &self,
        depth: usize,
        f: &mut std::fmt::Formatter<'_>,
        value_fmt: &dyn Fn(&T, &mut std::fmt::Formatter<'_>) -> std::fmt::Result,
    ) -> std::fmt::Result {
        let space = " ".repeat(depth * 2);
        match &self.kind {
            Kind::Leaf { value, .. } => {
                write!(f, "L({}, ", to_bin::<false>(&self.key))?;
                value_fmt(value, f)?;
                write!(f, ")")
            }
            Kind::Branch { mask, children, .. } => {
                write!(
                    f,
                    "B({}, {}, ",
                    to_bin::<false>(&self.key),
                    to_bin::<false>(&[*mask])
                )?;
                for (idx, child) in children.iter().enumerate() {
                    writeln!(f)?;
                    NodeLink::debug_fmt_impl(child, depth + 1, Some(idx), f, value_fmt)?;
                }
                write!(f, "\n{})", space)
            }
            Kind::Opaque(hash, _) => write!(f, "O({})", HashFrag::<H>(hash)),
        }
    }
}

#[cfg(test)]
mod witness_tests {
    use crate::digestible::{W, empty_hash};
    use crate::{Complete, Digest, Digestible, Trie};
    use allocator_api2::alloc::Global;
    use sha2::Sha256;
    use test_log::test;

    type U64BinaryTrie = Trie<W<u64>, 4, 2, Sha256, Global, Complete>;

    #[test]
    fn initial_node_has_initial_key() {
        let mut t: U64BinaryTrie = Trie::new();
        let initial_key = &[1, 2, 3];
        println!("Orig: {t:?}");
        t.set(initial_key, W(42)).unwrap();
        println!("Set: {t:?}");
        let (_hash, node) = t.1.0.unwrap();
        assert_eq!(&*node.key, initial_key);
    }

    #[test]
    fn preserves_key_and_digest() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1, 2, 3], W(42)).unwrap();
        let digest_before = t.digest();
        let witness = t.clone().to_partial();
        assert_eq!(witness.digest(), digest_before);
        assert_eq!(t.get(&[1, 2, 3]), witness.get(&[1, 2, 3]));
    }

    #[test]
    fn test_delete() {
        let mut t: U64BinaryTrie = Trie::new();
        println!("Empty: {t:?}");
        t.set(&[1, 2, 3], W(42)).unwrap();
        let orig = t.clone();
        println!("With 42: {t:?}");
        t.set(&[1, 2, 4], W(43)).unwrap();
        println!("With 43: {t:?}");
        t.delete(&[1, 2, 4]).unwrap();
        assert!(
            orig.hash_eq(&t),
            "Original and Deleted tries are unequal:\n{orig:?}\n{t:?}"
        );
        println!("With 42: {t:?}");
        t.delete(&[1, 2, 3]).unwrap();
        assert_eq!(t.digest(), empty_hash::<Sha256>());
        println!("Final: {t:?}");
    }

    #[test]
    fn witness_shape() {
        let mut t: U64BinaryTrie = Trie::new();
        t.set(&[1, 2, 3], W(42)).unwrap();
        println!("Orignal: {t:?}");
        t.set(&[1, 2, 4], W(43)).unwrap();
        println!("Orignal: {t:?}");
        let mut t = t.to_partial();
        t.prune_for_keys(vec![&[1]]);
        println!("Witness: {t:?}");
    }

    /// Regression test for a bug where inserting (or witnessing) a third key
    /// that required a second, nested branch decision within a single byte
    /// (e.g. `[1,2,3]`, `[1,2,4]`, `[1,2,5]` in a binary trie) would corrupt or
    /// lose one of the existing keys, because the bit position returned by a
    /// nested comparison was relative to the sliced key rather than absolute.
    #[test]
    fn nested_branch_keys_survive_insert_and_witness() {
        let mut t: U64BinaryTrie = Trie::new();
        let keys: &[&[u8]] = &[&[1, 2, 3], &[1, 2, 4], &[1, 2, 5], &[1, 2, 6], &[1, 2, 7]];
        for (i, key) in keys.iter().enumerate() {
            t.set(key, W(i as u64)).unwrap();
        }
        for (i, key) in keys.iter().enumerate() {
            assert_eq!(t.get(key), Ok(Some(&W(i as u64))), "key {key:?} lost after insert");
        }

        let all_keys = keys.to_vec();
        let expected = vec![Some(true); keys.len()];
        let clone_witness = t.to_witness_for_keys(all_keys.clone());
        assert!(clone_witness.verify_keys(&all_keys, &expected));
        let hash_witness = t.to_hash_witness_for_keys(all_keys.clone());
        assert!(hash_witness.verify_keys(&all_keys, &expected));
    }

    #[derive(Clone, Debug)]
    struct Data(u64);
    impl Digestible for Data {
        fn update_hasher<D: Digest>(&self, hasher: &mut D) {
            hasher.update(&self.0.to_le_bytes())
        }
    }

    type MyTrie = Trie<Data, 4, 2, Sha256, Global, Complete>;

    /// Mirrors the first `## Example Code` block in the README; kept in sync
    /// with it so the example can be debugged as a normal test.
    #[test]
    fn readme_example() {
        let mut t: MyTrie = Trie::new();
        t.set(&[1, 2, 3], Data(45)).unwrap();
        t.set(&[1, 2, 4], Data(78)).unwrap();
        t.set(&[1, 2, 5], Data(127)).unwrap();
        let delete_result = t.delete(&[1, 2, 4]);
        match delete_result {
            Ok(v) => println!("Old value at key was {v:?}"),
            Err(e) => println!("Error {e} occurred"),
        };
        let get_result = t.get(&[1, 2, 3]);
        match get_result {
            Ok(v) => println!("Borrow a value: {v:?}"),
            Err(e) => println!("Error {e} occurred"),
        }

        // if Trie data supports Clone/Debug, so does Trie
        let trie_clone = t.clone();
        println!("Trie clone: {trie_clone:?}");

        // build witnesses
        // NOTE: these construction techniques require `T: Clone`
        // as the witness tries may actually contain the underlying
        // trie values on leaf nodes
        let witness1 = t.to_witness_for_keys(vec![&[1, 2, 3]]);
        println!("Witness 1: {witness1:?}");

        let mut witness2 = t.clone().to_partial();
        witness2.prune_for_keys(vec![&[1, 2]]);
        println!("Witness 2: {witness2:?}");

        // verify witnesses
        // witness1:
        // - key [1,2,3] is provably present
        // - key [1,2,4] is provably absent (as lookup diverges before reaching the pruned subtrie)
        // - key [1,2,5]'s presence/absence is unprovable
        // provable from witness1 alone, so we don't assert anything about it here
        let witness1_keys: Vec<&[u8]> = vec![&[1, 2, 3], &[1, 2, 4], &[1,2,5]];
        let witness1_expected = vec![Some(true), Some(false), None];
        assert_eq!(witness1.verify_keys(&witness1_keys, &witness1_expected), true);

        // witness2:
        // since all of the leaf nodes in the trie are obscured, only
        // the search for key [1,2,4] has a provable absence
        let keys: Vec<&[u8]> = vec![&[1, 2, 3], &[1, 2, 4], &[1, 2, 5]];
        let expected = vec![None, Some(false), None];
        assert_eq!(witness2.verify_keys(keys, expected), true);
        println!("Final: {witness2:?}");
    }

    #[derive(Debug)]
    struct NonCloneData(u64);
    impl Digestible for NonCloneData {
        fn update_hasher<D: Digest>(&self, hasher: &mut D) {
            hasher.update(&self.0.to_le_bytes())
        }
    }

    type NonCloneTrie = Trie<NonCloneData, 4, 2, Sha256, Global, Complete>;

    /// Mirrors the second `## Example Code` block in the README (the
    /// `to_hash_witness_for_keys` example); kept in sync with it so the
    /// example can be debugged as a normal test.
    #[test]
    fn readme_hash_witness_example() {
        let mut t: NonCloneTrie = Trie::new();
        t.set(&[1, 2, 3], NonCloneData(45)).unwrap();
        t.set(&[1, 2, 4], NonCloneData(78)).unwrap();
        t.set(&[1, 2, 5], NonCloneData(127)).unwrap();

        // `t.clone()` and `t.to_witness_for_keys(..)` would both fail to compile here,
        // since `NonCloneData` does not implement `Clone`.
        let keys: Vec<&[u8]> = vec![&[1, 2, 3], &[1, 2, 4], &[1, 2, 5]];
        let witness = t.to_hash_witness_for_keys(keys.clone());
        println!("Hash witness: {witness:?}");

        let expected = vec![Some(true); keys.len()];
        assert_eq!(witness.verify_keys(&keys, &expected), true);
    }
}
