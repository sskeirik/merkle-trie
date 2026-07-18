#![cfg_attr(feature = "std_allocator_api", feature(allocator_api))]
//! A generic, Merkleized, compressed [Trie].
//!
//! Expanding upon the summary in more detail:
//!
//! 1. _[Trie]_ - A kind of tree such that:
//!
//!    1. keys are vieweed as sequences of atoms;
//!    2. the key of a node is the concatenation of all key fragments along the path from the root to the node.
//!
//!    In our case, keys are always byte strings (`&[u8]`).
//!
//! 2. _Compressed_ - Single-child nodes are merged with their parents.
//! 
//!    In particular, this means that Trie branches will always have at least 2 children.
//!
//! 3. _Merkleized_ - Each node has a cryptographic digest derived from its stored value and/or its children's digests.
//!
//!    This means that trie equality can be computed just by comparing trie root hashes (see [`Trie::hash_eq`]).
//!    Applying this property recursively means that we can represent sub-tries by their root hash,
//!    enabling an more powerful form of compression when the contents of a particular sub-trie are
//!    irrelevant for a given operation (see [`Trie::witness_for_keys`]).
//!
//! 4. _Generic_ - The implementation exposes the following user-settable generic parameters:
//!
//!    | Param | Bounds                    | Description                                                             |
//!    | ---   | ---                       | ---                                                                     |
//!    | `T`   | [`Digestible`]            | The value type stored in this trie                                      |
//!    | `N`   | [`usize`]                 | Max key length in bytes                                                 |
//!    | `K`   | [`usize`]                 | Node branching factor (2,4,16,256 - powers of two for fast bitwise ops) |
//!    | `H`   | [`Digest`]                | The hash function used for hash pointers                                |
//!    | `A`   | [`Allocator`] + [`Clone`] | The allocator used to store keys/values/nodes                           |
//!
//!    For dense tries, higher branching factors can reduce size overhead.
//!
//!    If `T` also implements [`Debug`]/[`Clone`], then [`Trie`] implements [`Debug`]/[`Clone`].
//!
//! # Limitations
//!
//! For implementation simplicity:
//! 
//! 1. Values can only be set on true leaf nodes (setting values on intermediate nodes is unsupported).
//! 
//! # Features
//! 
//! - `std_allocator_api` - defines `Allocator` as `std::alloc::Allocator` (currently requires nightly Rust);
//!    if unset, the `allocator-api2` shim package is used instead.

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
