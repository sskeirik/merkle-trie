#![cfg_attr(feature = "nightly", feature(allocator_api))]
/// Implements a compressed Merkle trie with a slightly simplified 
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

pub mod utils;
pub mod bitseqops;
pub mod digestible;
pub mod merkle;