/// Defines the Merkle Trie operations

use std::fmt::Debug;

use digest::{Digest, Output};
use tracing::instrument;

use crate::digestible::{Digestible, empty_hash};
use crate::utils::{Allocator, BitDiff, BitSeqOps, Box, find_first_distinct_bits, to_ascii, to_bin, to_hex, tz_mask};

use super::data::{Trie, TrieMode, Node, NodeUpdate, Kind};


impl<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest, M: TrieMode> Node<T,N,K,A,H,M> {
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
    #[instrument(skip_all)]
    pub fn set<U: NodeUpdate<T>>(&mut self, key: &[u8], index: usize, offset: usize, updater: U, alloc: A) -> Result<(), &'static str> {
        use Kind::*;

        let node_key = &self.key;
        let node_key_bits = self.get_key_bits();

        // tracing::debug!("SET: At node {:?} with node_key({}): {} and node_key_bits: {node_key_bits}, inserting key_suffix: {}", curr_node.dump_metadata(), node_key.len(), to_bin::<false>(&node_key), to_bin::<false>(&key_suffix));

        // QUESITON: It seems like node key stamping can be replaced with offsets which has the same effect.
        //           Would this simplify the codebase or make it more complex? 
        //           Such a move would change how trees are represented, but the trees themsevles would be isomorphic, I believe.
        // if the keys are distinct, we need to either split off a new node or continue searching
        let maybe_split = find_first_distinct_bits(&key[index..], node_key, offset, None, Some(node_key_bits));


        match (&mut self.kind, maybe_split) {
            // handle equalities
            (Branch { .. }, None) => { return Err("Cannot set key that is a proper prefix of an existing key") }
            (Leaf { value, .. }, None) => updater.on_occupied(value),
            // handle prefixes
            (_, Some(s)) if s.prefix == Some(0) => { return Err("Cannot set key that is a proper prefix of an existing key") },
            (Leaf { .. }, Some(s)) if s.prefix == Some(1) => { return Err("Cannot set key that is a proper suffix of an existing leaf") }
            (Branch { children, .. }, Some(s)) if s.prefix == Some(1) => { 
                // in this case, we must compute child slot, set it if it doesn't exist, and search recursively if it doesn't
                tracing::debug!("Branch: node_key < key: {:?}", s);
                let slot = s.slot::<K>(key);
                // if a child node already exists, search recursively
                if let Some((hash, child)) = children[slot].as_mut() {
                    // tracing::debug!("selecting children[{slot}]=({},{})", to_hex::<false>(&hash[0..4]), child.dump_metadata());
                    child.set(key, s.index, s.bits, updater, alloc.clone())?;
                    *hash = child.digest();
                // otherwise, create one, if we have an initializer
                } else {
                    if let Some(value) = updater.on_vacant() {
                        tracing::debug!("creating new leaf with next_key");
                        let key = s.write_suffix::<K,A>(key, alloc.clone());
                        let leaf = Self { key, kind: Kind::Leaf { value, _phantom: std::marker::PhantomData }};
                        children[slot] = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
                    } else {
                        return Err("Cannot create leaf with null initializer")
                    }
                }
            }
            // handle opaque
            (Opaque(_), _) => return Err("Cannot set value inside an opaque branch"),
            // handle diffs
            (_, Some(s)) => {
                // in this case, we must create:
                // 1. a new branch node to encapsulate this diff
                // 2. a new leaf node for our newly set value
                if let Some(value) = updater.on_vacant() {
                    debug_assert!(s.prefix.is_none(), "internal error: prefix case was not properly handled");
                    let mut children = [const { None }; K];
                    // create new leaf node for key and new_value
                    let new_child = Self { key: s.write_suffix::<K,A>(key, alloc.clone()), kind: Kind::Leaf { value, _phantom: std::marker::PhantomData } };
                    // tracing::debug!("new leaf: {}", new_child.dump_metadata());
                    // set up children array
                    children[s.slot::<K>(key)] = Some((new_child.digest(), Box::new_in(new_child, alloc.clone())));
                    // update existing node memory with new branch
                    let new_branch = Self { key: s.write_prefix::<K,A>(key, alloc.clone()), kind: Kind::Branch { mask: s.mask::<K>(), children }};
                    // tracing::debug!("new branch: {}, old node: {}", new_branch.dump_metadata(), curr_node.dump_metadata());
                    let old_self_slot = s.slot::<K>(node_key);
                    let old_self_key = s.write_suffix::<K,A>(node_key, alloc.clone());
                    let mut old_self = std::mem::replace(self, new_branch);
                    // update old_self's key and make it a child of the current self (a branch)
                    old_self.key = old_self_key;
                    unsafe { self.raw_set_child(old_self_slot, old_self, None, alloc.clone())? };
                } else {
                    return Err("Cannot create leaf with null initializer")
                }
            }
        }

        Ok(())
    }

    /// returns number of bits in node key
    /// for a branch, this is all of the bits in the prefix, excluding all bits in its final byte that overlap/succeed the diff
    /// for a leaf, this is all of the bits in its key
    #[inline]
    fn get_key_bits(&self) -> usize {
        let mask_0s = match self.kind {
            Kind::Branch { mask, .. } => mask.trailing_zeros(),
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
            Kind::Branch { children, .. } => children[idx] = Some((hash, node)),
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
            Kind::Branch { mask, children } => {
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