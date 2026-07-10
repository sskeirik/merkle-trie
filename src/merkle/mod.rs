//! Defines a generic, Merkleized, compressed trie.

/// Defines the underlying data types that encode the trie.
pub mod types;
/// Defines the public API for [`types::Trie`].
pub mod api;
/// Defines all internal operations
pub mod internal;