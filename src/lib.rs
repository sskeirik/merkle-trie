#![cfg_attr(feature = "std_allocator_api", feature(allocator_api))]
#![doc = include_str!("../README.md")]

pub mod utils;
pub mod bitseqops;
pub(self) mod digestible;
pub(self) mod api;
pub(self) mod types;
mod internal;

// Public re-exports
pub use types::{Trie, Complete, Partial, TrieError};
pub use types::NodeUpdate;
pub use digestible::Digestible;

#[allow(unused_imports)] // for doc-comments
use {
    digest::Digest,
    utils::Allocator,
};
