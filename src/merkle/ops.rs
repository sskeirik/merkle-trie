/// Defines the Merkle Trie operations

use std::fmt::Debug;

use digest::{Digest, Output};
use tracing::instrument;

use crate::digestible::Digestible;
use crate::utils::{Allocator, Box, find_first_distinct_bits};
use crate::unreachable_checked;

use super::data::{Trie, TrieMode, Node, Kind, Concrete, Witness};


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
    pub fn set(&self, key: &[u8], offset: usize, initializer: Option<T>, updater: Option<impl FnOnce(&mut T)>, alloc: A) -> Result<(), &'static str> {

        let node_key = self.key;

        tracing::debug!("SET: At node {:?} with node_key({}): {} and node_key_bits: {node_key_bits}, inserting key_suffix: {}", curr_node.dump_metadata(), node_key.len(), to_bin::<false>(&node_key), to_bin::<false>(&key_suffix));

        // if the keys are distinct, we need to either split off a new node or continue searching
        let maybe_split = find_first_distinct_bits(key, None, &node_key, Some(node_key_bits));

        // restore edge byte
        if key.len() > node_key.len() {
            key[node_key.len()] = edge_byte
        }

        match (&mut **curr_node, maybe_split) {
            // handle equalities
            (Branch { .. }, None) => { return Err("Cannot set key that is a proper prefix of an existing key") }
            (Leaf { value, .. }, None) => { 
                if let Some(updater) = updater {
                    updater(value)
                } else if let Some(initializer) = initializer {
                    *value = initializer
                } else {
                    return Err("Did not specify intializer or updater")
                }; 
            },
            // handle prefixes
            (_, Some(s)) if s.proper_prefix() == Some(0) => { return Err("Cannot set key that is a proper prefix of an existing key") },
            (Leaf { .. }, Some(s)) if s.proper_prefix() == Some(1) => { return Err("Cannot set key that is a proper suffix of an existing leaf") }
            (Branch { prefix, mask, children  }, Some(s)) if s.proper_prefix() == Some(1) => { 
                // in this case, we must compute child slot, set it if it doesn't exist, and search recursively if it doesn't
                tracing::debug!("Branch: node_key < key: {:?}", s);
                debug_assert_eq!(**prefix, node_key);
                // get fragment of key not covered by node_key
                let next_key = &mut key[prefix.len() - 1..];
                tracing::debug!("next_key: {}", to_bin::<false>(next_key));
                // compute the child slot
                let slot = compute_key_idx(next_key, *mask);
                // stamp the suffix
                let orig_suffix_byte = stamp_suffix(next_key, *mask);
                // if a child node already exists, search recursively
                if let Some(child) = children[slot].as_mut() {
                    tracing::debug!("selecting children[{slot}]=({},{})", to_hex::<false>(&child.0[0..4]).unwrap(), child.1.dump_metadata());
                    Self::set(child, next_key, initializer, updater, buf_p, buf_a, buf_b, alloc.clone())?;
                // otherwise, create one, if we have an initializer
                } else {
                    if let Some(initializer) = initializer {
                        tracing::debug!("creating new leaf with next_key");
                        let key = Self::alloc(next_key, alloc.clone())?;
                        let leaf = Self::Leaf { key, value: initializer, _phantom: std::marker::PhantomData };
                        children[slot] = Some((leaf.digest(), Box::new_in(leaf, alloc.clone())));
                    } else {
                        return Err("Cannot create leaf with null initializer")
                    }
                }
                // restore original suffix byte
                next_key[0] = orig_suffix_byte;
            }
            // handle diffs
            (_, Some(s)) => {
                // in this case, we must create:
                // 1. a new branch node to encapsulate this diff
                // 2. a new leaf node for our newly set value
                if let Some(initializer) = initializer {
                    debug_assert!(s.proper_prefix().is_none(), "internal error: prefix case was not properly handled");
                    let BitSplit { prefix, suffixes, kind: Diff { mask, values } } = s else {
                        unsafe { std::hint::unreachable_unchecked() }
                    };
                    let prefix = Self::alloc(prefix, alloc.clone())?;
                    let mut children = [const { None }; K];
                    // create new leaf node for key and new_value
                    let new_child = Self::Leaf { key: Self::alloc(suffixes[0], alloc.clone())?, value: initializer, _phantom: std::marker::PhantomData };
                    tracing::debug!("new leaf: {}", new_child.dump_metadata());
                    // set up children array
                    children[values[0]] = Some((new_child.digest(), Box::new_in(new_child, alloc.clone())));
                    // update existing node memory with new branch
                    let new_branch = Self::Branch { prefix, mask, children };
                    tracing::debug!("new branch: {}, old node: {}", new_branch.dump_metadata(), curr_node.dump_metadata());
                    let mut old_curr = std::mem::replace(&mut **curr_node, new_branch);
                    // change key segment of new node
                    old_curr.set_key(Self::alloc(suffixes[1], alloc.clone())?);
                    // set old_curr as child of new branch
                    unsafe { curr_node.set_child(values[1], old_curr, None, alloc.clone())? };
                } else {
                    return Err("Cannot create leaf with null initializer")
                }
            }
        }

        // fixup hashptr
        curr_hash.copy_from_slice(&curr_node.digest());

        Ok(())
    }
}