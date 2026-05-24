/// Defines the Merkle Trie operations

use std::fmt::Debug;

use digest::{Digest, Output};
use tracing::instrument;

use crate::digestible::{Digestible, empty_hash};
use crate::utils::{Allocator, BitDiff, BitPosition, BitSeqOps, Box, find_first_distinct_bits, to_ascii, to_bin, to_hex, tz_mask};

use super::data::{Trie, TrieMode, Node, NodeUpdate, Kind, BranchData};

pub(crate) enum FindResult<N,B> {
    ExactMatch(N),
    EmptySlot(B, usize),
    Disagreement(N, BitDiff),
}

impl<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest, M: TrieMode> Node<T,N,K,A,H,M> {

    pub(crate) fn find<'a, R>(&'a self, key: &[u8], pos: BitPosition, action: impl FnOnce(BitPosition, FindResult<&'a Self, &'a BranchData<T,N,K,A,H,M>>) -> R) -> R {

        // if keys are identical, return current node and lack of diff
        let Some(split) = find_first_distinct_bits(&key[pos.index..], &self.key, pos.bits, None, Some(self.get_key_bits())) else {
            return action(pos, FindResult::ExactMatch(self))
        };

        // otherwise, check if we can explore a subtrie
        match (&self.kind, split.prefix) {
            (Kind::Branch(branch), Some(1)) => {
                let slot = split.slot::<K>(key);
                if let Some((_hash, child)) = branch.children[slot].as_ref() {
                    child.find(key, split.pos, action)
                } else {
                    action(pos, FindResult::EmptySlot(branch,slot))
                }
            },
            // no subtrie to explore, return
            _ => action(pos, FindResult::Disagreement(self, split))
        }
    }

    // #[instrument(skip_all)]
    pub(crate) fn find_mut<R>(&mut self, hash: Option<&mut Output<H>>, key: &[u8], pos: BitPosition, action: impl FnOnce(BitPosition, FindResult<&mut Self, &mut BranchData<T,N,K,A,H,M>>) -> R) -> R {

        // if keys are identical, return current node and lack of diff
        let Some(split) = find_first_distinct_bits(&key[pos.index..], &self.key, pos.bits, None, Some(self.get_key_bits())) else {
            return action(pos, FindResult::ExactMatch(self))
        };

        // otherwise, check if we can explore a subtrie
        let result = match (&mut self.kind, split.prefix) {
            (Kind::Branch(branch), Some(1)) => {
                let slot = split.slot::<K>(key);
                if let Some((hash, child)) = branch.children[slot].as_mut() {
                    child.find_mut(Some(hash), key, split.pos, action)
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
                _ => Err("Unsupported trie set")
            }
        };
        self.find_mut(hash, search_key, BitPosition { index: 0, bits: 0 }, action)
    }


    pub fn get<'a>(&'a self, search_key: &[u8]) -> Option<&'a T> {
        use FindResult::*;
        let action = |_pos, result: FindResult<&'a Self, &'a BranchData<T,N,K,A,H,M>>| {
            match result {
                ExactMatch(Node { kind: Kind::Leaf { value, .. }, .. }) => Some(value),
                _ => None,
            }
        };
        self.find(search_key, BitPosition { index: 0, bits: 0 }, action)
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
            Kind::Opaque(witness) => M::digest_opaque(witness),
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