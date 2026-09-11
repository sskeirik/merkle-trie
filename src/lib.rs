#![cfg_attr(feature = "std_allocator_api", feature(allocator_api))]
#![doc = include_str!("../README.md")]

pub mod bitseqops;
mod digestible;
mod node;
mod trie;
pub mod utils;

// Public re-exports
pub use digest::Digest;
pub use digestible::{Digestible, HashWitnessValue};
pub use node::{Complete, Partial, TrieMode};
pub use trie::{NodeUpdate, Trie, TrieError};
