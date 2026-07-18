#![cfg_attr(feature = "std_allocator_api", feature(allocator_api))]
#![doc = include_str!("../README.md")]

pub mod utils;
pub mod bitseqops;
mod digestible;
mod trie;
mod node;

// Public re-exports
pub use trie::{Trie, TrieError, NodeUpdate};
pub use node::{Complete, Partial};
pub use digestible::Digestible;

#[allow(unused_imports)] // for doc-comments
use {
    digest::Digest,
    utils::Allocator,
};
