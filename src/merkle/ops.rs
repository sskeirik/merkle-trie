use std::collections::HashMap;
/// Defines the Merkle Trie operations

use std::fmt::Debug;

use digest::{Digest, Output};
use itertools::{EitherOrBoth, Itertools};
use tracing::instrument;

use crate::digestible::{Digestible, empty_hash};
use crate::merkle::data::Kind::Opaque;
use crate::utils::{Allocator, BitDiff, BitPosition, BitSeqOps, Box, find_first_distinct_bits, to_ascii, to_bin, to_hex, tz_mask, pick_mut_unchecked};

use super::data::{Trie, TrieMode, Node, NodeUpdate, Kind, BranchData, Concrete, Partial};

pub(crate) enum FindResult<N,B> {
    ExactMatch(N),
    EmptySlot(B, usize),
    Disagreement(N, BitDiff),
    Bounded(BitPosition, N, usize),
}

impl<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest, M: TrieMode> Node<T,N,K,A,H,M> {

    pub(crate) fn find<'a, R>(&'a self, mut bound: Option<usize>, key: &[u8], pos: BitPosition, action: impl FnOnce(BitPosition, FindResult<&'a Self, &'a BranchData<T,N,K,A,H,M>>) -> R) -> R {
        // if keys are identical, return current node and lack of diff
        let Some(split) = find_first_distinct_bits(&key[pos.index..], &self.key, pos.bits, None, Some(self.get_key_bits())) else {
            return action(pos, FindResult::ExactMatch(self))
        };

        // otherwise, check if we can explore a subtrie
        match (&self.kind, split.prefix) {
            (Kind::Branch(branch), Some(1)) => {
                let slot = split.slot::<K>(key);
                if let Some((_hash, child)) = branch.children[slot].as_ref() {
                    match bound {
                        Some(0) => return action(pos, FindResult::Bounded(split.pos, self, slot)),
                        Some(ref mut n) => *n -= 1,
                        _ => {}
                    };
                    child.find(bound, key, split.pos, action)
                } else {
                    action(pos, FindResult::EmptySlot(branch,slot))
                }
            },
            // no subtrie to explore, return
            _ => action(pos, FindResult::Disagreement(self, split))
        }
    }

    // #[instrument(skip_all)]
    pub(crate) fn find_mut<R>(&mut self, mut bound: Option<usize>, hash: Option<&mut Output<H>>, key: &[u8], pos: BitPosition, action: impl for <'a> FnOnce(BitPosition, FindResult<&'a mut Self, &'a mut BranchData<T,N,K,A,H,M>>) -> R) -> R {
        // if keys are identical, return current node and lack of diff
        let Some(split) = find_first_distinct_bits(&key[pos.index..], &self.key, pos.bits, None, Some(self.get_key_bits())) else {
            return action(pos, FindResult::ExactMatch(self))
        };

        // otherwise, check if we can explore a subtrie
        let result = match (&mut self.kind, split.prefix) {
            (Kind::Branch(branch), Some(1)) => {
                let slot = split.slot::<K>(key);
                if let Some((hash, child)) = branch.children[slot].as_mut() {
                    match bound {
                        Some(0) => return action(pos, FindResult::Bounded(split.pos, self, slot)),
                        Some(ref mut n) => *n -= 1,
                        _ => {}
                    };
                    child.find_mut(bound, Some(hash), key, split.pos, action)
                } else {
                    action(pos, FindResult::EmptySlot(branch, slot))
                }
            },
            // no subtrie to explore, return
            _ => action(pos, FindResult::Disagreement(self, split))
        };
        // fixup our hash if we have one
        hash.map(|h| *h = self.digest());
        result
    }

    /// Given key_suffix, find existing descendant node that matches key_suffix and set its value to new_value
    /// otherwise, if matching descendant node does not exist, create one and set its value to new_value
    /// 
    /// This is the most complex function in the trie; there are eight possible cases defined by two independent choices:
    /// 
    /// 1. The current node is either (2 cases):
    /// 
    ///    - a leaf(node_key, value)
    ///    - a brch(node_key, [child1,...,childK])
    // 
    ///    Note: to describe the common elements of a generic node, we write NODE(node_key)
    /// 
    /// 2. When comparing the key_suffix and node_key, their relationship is as follows (4 cases):
    ///    - key_suffix == node_key
    ///    - key_suffix <  node_key (key_suffix is a prefix of node_key)
    ///    - node_key   <  key_suffix
    ///    - key_suffix != node_key
    /// 
    /// We describe the required behavior of each case defined above.
    /// Some cases must make additional distinctions.
    /// 
    /// Let P = key_suffix.len() and Q = node_key.len().
    /// If key_suffix != node_suffix, let C be the length of their longest common prefix.
    /// 
    /// 1. (leaf(node_key,value),      key_suffix == node_key  ) -> overwrite value by new_value
    /// 1. (brch(node_key,children),   key_suffix == node_key  ) -> error
    /// 2. (NODE(node_key),            key_suffix != node_key  ) -> branch(common_prefix, NULL,   [...,leaf(key_suffix[C..], new_value), NODE(node_key[C..]),...])
    /// 
    ///    NOTE: in this case, we need to set the child nodes in the correct slot based on the diff values.
    /// 
    /// 3. (brch(node_key,value,chld), node_key   <  key_suffix):
    ///    - if chld[key_suffix[Q]] == NULL                      -> set chld[key_suffix[Q]] to leaf(key_suffix[Q..])
    ///    - otherwise                                           -> call set on chld[key_suffix[Q]] 
    /// 4. (NODE(node_key),            key_suffix <  node_key  ) -> error
    /// 5. (leaf(node_key,value),      node_key   <  key_suffix) -> error
    /// 
    /// NOTE: at the cost of more complexity in set and an extra pointer on branch nodes, cases 4-5 could be supported
    pub fn set<U: NodeUpdate<T>>(&mut self, hash: Option<&mut Output<H>>, search_key: &[u8], updater: U, alloc: A) -> Result<(), &'static str> {
        use Kind::*;
        use FindResult::*;
        let action = move |pos: BitPosition, find_result: FindResult<&mut Self, &mut BranchData<T,N,K,A,H,M>>| {
            match find_result {
                EmptySlot(branch, slot) => {
                    if let Some(value) = updater.on_vacant() {
                        let key = BitSeqOps::<K>::write_aligned_suffix::<A>(&pos, search_key, alloc.clone());
                        let leaf = Self { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }};
                        branch.children[slot] = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
                        Ok(())
                    } else {
                        Err("Cannot create leaf with null initializer")
                    }
                }
                ExactMatch(Node { kind: Leaf { value, .. }, .. }) => Ok(updater.on_occupied(value)),
                Disagreement(curr, split) => {
                    if split.prefix.is_some() {
                        return Err("Cannot set a value on a prefix");
                    }
                    let Some(value) = updater.on_vacant() else {
                        return Err("Cannot create leaf with null initializer")
                    };
                    let mut children = [const { None }; K];
                    // create new leaf node for search_key and new_value
                    let new_child = Self { key: split.write_suffix::<K,A>(search_key, alloc.clone()), kind: Kind::Leaf { value, _phantom: std::marker::PhantomData } };
                    // tracing::debug!("new leaf: {}", new_child.dump_metadata());
                    // set up children array
                    children[split.slot::<K>(&curr.key)] = Some((new_child.digest(), Box::new_in(new_child, alloc.clone())));
                    // update existing node memory with new branch
                    let new_branch = Self { key: split.write_prefix::<K,A>(&curr.key, alloc.clone()), kind: Kind::Branch(BranchData { mask: split.mask::<K>(), children }) };
                    // tracing::debug!("new branch: {}, old node: {}", new_branch.dump_metadata(), curr_node.dump_metadata());
                    let old_curr_slot = split.slot::<K>(&curr.key);
                    let old_curr_key = split.write_suffix::<K,A>(&curr.key, alloc.clone());
                    let mut old_curr = std::mem::replace(curr, new_branch);
                    // update old_self's key and make it a child of the current self (a branch)
                    old_curr.key = old_curr_key;
                    unsafe { curr.raw_set_child(old_curr_slot, old_curr, None, alloc.clone())? };
                    Ok(())
                }
                Bounded(..) => unreachable!("Bound not set"),
                _ => Err("Unsupported trie set")
            }
        };
        self.find_mut(None, hash, search_key, BitPosition { index: 0, bits: 0 }, action)
    }


    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        use FindResult::*;
        let action = |_pos, result: FindResult<&'a Self, &'a BranchData<T,N,K,A,H,M>>| {
            match result {
                ExactMatch(Node { kind: Kind::Leaf { value, .. }, .. }) => Some(value),
                Bounded(..) => unreachable!("Bound not set"),
                _ => None,
            }
        };
        self.find(None, search_key, BitPosition { index: 0, bits: 0 }, action)
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

    /// Sets a child on this node which must be a branch
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
    
    #[inline]
    /// Retrieves a child from this node
    /// SAFTEY: must ensure caller is a branch and idx is within bounds
    unsafe fn raw_get_child(&mut self, idx: usize) -> &mut Option<(Output<H>, Box<Self,A>)> {
        match &mut self.kind {
            Kind::Branch(BranchData { children, .. }) => unsafe { children.get_unchecked_mut(idx) },
            // SAFETY: by assumption
            Kind::Leaf { .. } | Kind::Opaque(..) => unsafe { std::hint::unreachable_unchecked() },
        }
    }

    pub fn num_children(&self) -> Option<usize> {
        match &self.kind {
            Kind::Branch(BranchData { children , .. }) => Some(children.len()),
            _ => None
        }
    }

    pub fn digest(&self) -> Output<H> {
        let mut hasher = H::new();
        if let Some(precomputed_digest) = self.digest_internal(&mut hasher) {
            precomputed_digest
        } else {
            hasher.finalize()
        }
    }

    fn digest_internal<D: Digest>(&self, hasher: &mut D) -> Option<Output<H>> {
        Digest::update(hasher, &self.key);
        match &self.kind {
            Kind::Opaque(hash, _marker) => Some(hash.clone()),
            Kind::Leaf { value, .. } => {
                value.digest_update( hasher);
                None
            }
            Kind::Branch(BranchData { mask, children }) => {
                Digest::update(hasher, [*mask]);
                for child in children {
                    if let Some((hash, _)) = child {
                        Digest::update(hasher, hash);
                    } else {
                        Digest::update(hasher, empty_hash::<H>());
                    }
                }
                None
            }
        }
    }
}

impl<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest> Node<T,N,K,A,H,Concrete> {
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
impl<T: Debug + Digestible + Clone, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest + Clone> Node<T,N,K,A,H,Partial> {
    pub fn witness_for_keys(&mut self, mut keys: Vec<&[u8]>) {
        keys.sort();
        keys.dedup();
        let keys: Vec<_> = keys.into_iter().map(|k| (k, 0)).collect();
        let mut frontier = vec![(self, keys)];

        // in this loop, we repeatedly prune nodes that are NOT in our frontier
        while frontier.len() != 0 {
            frontier = frontier.into_iter().flat_map(|(node, keys)| {

                // if this node is terminal, return immediately
                if node.num_children().is_none() {
                    return vec![];
                }

                // for each key, find the keys that reach a particular child slot
                let mut per_node_keys= HashMap::new();
                for (key, bits) in keys.into_iter() {
                    node.find(Some(0), key, BitPosition { index: 0, bits }, |_, res| {
                        match res {
                            FindResult::Bounded(p, _, slot) => {
                                let keys: &mut Vec<_> = per_node_keys.entry(slot).or_default();
                                keys.push((&key[p.index..], p.bits));
                            }
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
                let mut indices = Vec::with_capacity(K);
                for idx in 0..K {
                    if per_node_keys.contains_key(&idx) {
                        indices.push(idx);
                    } else {
                        if let Some(Some((hash, child))) = children.get_mut(idx) {
                            child.kind = Opaque(hash.clone(), ())
                        }
                    }
                }

                // SAFETY: all indices are disjoint and in-bounds by construction from our loop above
                // here, we grab unique mutable references to the reachable children of this node, which is valid due to disjointness
                let local_frontier: Vec<_> = unsafe { pick_mut_unchecked(children, &indices) };

                // finally, we expand the frontier vector for each child node
                indices.into_iter().zip(local_frontier.into_iter()).map(|(child_idx, node)| {
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
    use super::*;
    use allocator_api2::alloc::Global;
    use sha2::Sha256;

    // Regression test for `to_witness`'s transmute: a plain `cargo build` type-checks
    // the generic definition but never monomorphizes it (nothing in the crate calls
    // it), so a transmute that's unsound - or that simply fails to compile - for a
    // concrete instantiation can hide behind a green build. Instantiating it here
    // with a concrete allocator and hasher is what actually exercises the check.
    #[test]
    fn preserves_key_and_digest() {
        let leaf: Node<u64, 4, 2, Global, Sha256, Concrete> = Node {
            key: crate::utils::copy_slice_into_box(&[1, 2, 3], Global),
            kind: Kind::Leaf { value: 42u64, _phantom: std::marker::PhantomData },
        };
        let digest_before = leaf.digest();
        let key_before = leaf.key.to_vec();

        let witness = leaf.to_partial();

        assert_eq!(witness.key.to_vec(), key_before);
        assert_eq!(witness.digest(), digest_before);
    }
}