//! Merkle [`Trie`] data types.
use digest::{Digest, Output};
use crate::digestible::Digestible;
use crate::utils::{Allocator, Box};

/// A generic, compressed Merkleized trie.
/// 
/// We describe its generic paramters below:
/// 
/// | Param | Bounds                     | Description                                                             |
/// | ---   | ---                        | ---                                                                     |
/// | `T`   | [`Digestible`]             | The value type stored in this trie                                      |
/// | `N`   | [`usize`]                  | Max key length in bytes                                                 |
/// | `K`   | [`usize`]                  | Node branching factor (2,4,16,256 - powers of two for fast bitwise ops) |
/// | `H`   | [`Digest`]                 | The hash function used for hash pointers                                |
/// | `A`   | [`Allocator`] + [`Clone`]  | The allocator used to store keys/values/nodes                           | 
///
/// For dense tries, higher branching factors can reduce size overhead.
///
/// If `T` also implements [`Debug`]/[`Clone`], then [`Trie`] will implements [`Debug`]/[`Clone`].
#[derive(Clone)]
pub struct Trie<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>(pub(super) A, pub(super) NodeLink<T,N,K,H,A,M>);

/// Errors that can occur while performing [`Trie`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrieError {
    /// The provided key was empty or exceeded the trie's maximum key length.
    InvalidKeyLength,
    /// A leaf could not be created because no initial value was supplied.
    MissingInitializer,
    /// The target key resolved to a node whose kind does not support this update.
    UnsupportedSet,
    /// The target key is a prefix of an existing key, or vice versa, so no value can be set there.
    SetOnPrefix,
}

impl std::fmt::Display for TrieError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            Self::InvalidKeyLength => "key length is invalid",
            Self::MissingInitializer => "cannot create leaf with null initializer",
            Self::UnsupportedSet => "unsupported trie set",
            Self::SetOnPrefix => "cannot set a value on a prefix",
        };
        write!(f, "{msg}")
    }
}

impl std::error::Error for TrieError {}

/// A node in a Merkleized, compressed trie.
/// 
/// The `repr(C)` attribute ensures a consistent representation across the distinct [`TrieMode`]s
/// 
/// This type is made public for documentation purposes, but since
/// the [`Trie`] internals are private, it cannot be directly used
/// for [`Trie`] introspection.
 #[derive(Clone)]
 #[repr(C)]
pub(super) struct Node<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode> {
    /// the whole bytes that must be matched to visit this node
    pub key: Box<[u8],A>,
    /// the node's kind-specific data
    pub kind: Kind<T,N,K,H,A,M>,
}

/// A generic Merkle trie node payload
/// 
/// The `repr(C,u8)` attribute ensures a consistent representation across the distinct [`TrieMode`]s
/// 
/// This type is made public for documentation purposes, but since
/// the [`Trie`] internals are private, it cannot be directly used
/// for [`Trie`] introspection.
#[derive(Clone)]
#[repr(C, u8)]
pub(super) enum Kind<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode> {
    /// A trie branch
    Branch {
        /// Encodes the log2(`K`) bits in the [`Node::key`]`.len()`th byte that distinguishes the keys of child nodes
        mask: u8,
        /// Stores the `K` child nodes of this branch
        children: [NodeLink<T,N,K,H,A,M>; K],
    },
    /// A trie leaf
    Leaf {
        /// the data stored at this leaf
        value: T,
        /// zero-sized type that exists to record the hash algorithm used by this trie
        _phantom: std::marker::PhantomData<H>,
    },
    /// Witness for a subtrie of unknown shape (only constructible if [`TrieMode`] is set to [`Partial`]).
    Opaque(Output<H>, M::Marker),
}

/// The hash reference contained inside a [`NodeLink`]
pub(super) type NodeLinkInner<T,const N: usize, const K: usize, H, A, M> = (Output<H>, Box<Node<T,N,K,H,A,M>, A>);

/// A nullable link between [`Node`]s in a [`Trie`]
#[derive(Clone)]
pub(super) struct NodeLink<T: Digestible, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode>(
    pub Option<NodeLinkInner<T,N,K,H,A,M>>,
);

// Opaque [`Irie`] Node Tag Type.
mod sealed { pub trait SealedTrieMode {} }
pub use mode::{Complete, Partial};
pub mod mode {
    #[allow(unused_imports)] // for doc-comments
    use super::{Trie, Kind};
    /// Marker type that forces a [`Trie`] to be complete (i.e., it _cannot_ contain opaque nodes).
    #[derive(Clone)]
    pub struct Complete;
    /// Marker type that permits a [`Trie`] to be partial (i.e., it _may_ contain opaque nodes).
    #[derive(Clone)]
    pub struct Partial;
    impl super::sealed::SealedTrieMode for Complete {}
    impl super::sealed::SealedTrieMode for Partial {}
    impl super::TrieMode for Complete {
        type Marker = std::convert::Infallible;
    }
    impl super::TrieMode for Partial {
        type Marker = ();
    }
}

/// Trait that describes whether a [`Trie`] may be partial
/// (i.e., may contain [`Kind::Opaque`] nodes).
pub trait TrieMode: sealed::SealedTrieMode {
    /// ZST tag stored in [`Kind::Opaque`] nodes.  
    /// In [`Complete`] tries, resolves to the empty type
    /// (preventing construction of opaque nodes).
    type Marker: Clone;
}


/// Trait that describes how to update the value stored in a [`Trie`] node.
/// 
/// A [`std::collections::hash_map::Entry`]-style API does not work well
/// for Merkleized data structures (like our [`Trie`]) because returning
/// a mutable reference to a node means callers may inadvertantly invalidate
/// previously computed node hashes, requiring calls to [`Trie::digest`]
/// to rewalk the entire trie to ensure hash freshness.
/// 
/// Instead, we use a more heavyweight trait-based API that injects any
/// custom update logic into the execution of [`Trie::update`] itself, so that
/// our update function can recalculate node hashes as needed, once-and-for-all.
/// 
/// We compare our approach to two alternative approaches below:
///  
/// 1. Use a pair of `Option<T>` and `FnOnce(&mut T)`.
/// 
///    This works _but_ memory must be duplicated between the two
///    values used for the vacant and occupied cases.
/// 
/// 2. Make [`NodeUpdate::on_occupied`] take a closure `FnOnce(&mut T)`.
/// 
///    This does not provide any extra generality (since we can
///    always represent custom logic via a new trait impl), and 
///    we hit the same problem described in point (1).
pub trait NodeUpdate<T> {
    /// How to update a node value when a prior value already exists.
    /// 
    /// It is the implementor's resposibility to ensure that this function
    /// actually overwrites the mutable input reference.
    /// 
    /// If an implementation fails to conform to the above requirement,
    /// it will be sound, but useless for overwriting existing values.
    fn on_occupied(self, existing_value: &mut T);

    /// The value to insert if no value is currently present;
    /// Returning [None] will cause this operation to fail for non-existent values,
    /// enabling insert-without-overwriting semantics.
    fn on_vacant(self) -> Option<T>;
}

/// Implements [`NodeUpdate`] by upserting [`Self::value`].
pub(super) struct NodeUpsert<T> {
    /// The value to be upserted.
    pub value: T
}

/// Updates a node's value by upsertion of the stored value.
impl<T> NodeUpdate<T> for NodeUpsert<T> {
    fn on_occupied(self, existing_value: &mut T) {
        *existing_value = self.value;
    }

    fn on_vacant(self) -> Option<T> {
        Some(self.value)
    }
}

/// Basic trait implementations for primary types.
mod basic_trait_impls {
    use super::*;
    use std::fmt::Debug;
    use crate::digestible::HashFrag;
    #[allow(unused_imports)] // debugging or doc-comments
    use crate::utils::{to_ascii, to_bin, to_hex};

    /// Trie/node equality is just equality of its node structure
    impl<T: Digestible + PartialEq + Eq, const N: usize, const K: usize, H: Digest, A: Allocator + Clone, M: TrieMode> PartialEq for Trie<T,N,K,H,A,M> {
        fn eq(&self, other: &Self) -> bool {
            self.1 == other.1
        }
    }

    /// Trie/node equality is just equality of its node structure.
    impl<T: Digestible + PartialEq + Eq, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> PartialEq for NodeLink<T,N,K,H,A,M> {
        fn eq(&self, other: &Self) -> bool {
            use Kind::*;
            match (&self.0, &other.0) {
                (Some((_, node1)), Some((_, node2))) => {
                    node1.key == node2.key && match (&node1.kind, &node2.kind) {
                        (Leaf { value: v1, ..  }, Leaf { value: v2, .. }) => v1 == v2,
                        (Opaque(digest1, _), Opaque(digest2, _)) => digest1 == digest2,
                        (Branch { mask: m1, children: c1 }, Branch { mask: m2, children: c2 }) => {
                            m1 == m2 && c1.iter().zip(c2.iter()).all(|(c1, c2)| c1 == c2 )
                        }
                        (_, _) => false,
                    }
                }
                (None, None) => true,
                _ => false,
            }
        }
    }

    /// The debug format of a Merkle trie/node is a nested presentation of the trie structure
    impl<T: Digestible + Debug, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> Debug for Trie<T,N,K,H,A,M> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.1.debug_fmt( 0, None, f)
        }
    }

    /// The debug format of a Merkle trie/node is a nested presentation of the trie structure
    impl<T: Digestible + Debug, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> Debug for NodeLink<T,N,K,H,A,M> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            self.debug_fmt( 0, None, f)
        }
    }

    impl<T: Digestible + Debug, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> NodeLink<T,N,K,H,A,M> {
        /// This function drives the [`Debug`] implementation for [`Trie`].
        pub(super) fn debug_fmt(&self, depth: usize, child_num: Option<usize>, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let space = " ".repeat(depth*2);
            write!(f, "{}", space)?;
            if let Some(child_num) = child_num {
                write!(f, "{:>3}: ", child_num)?;
            }
            if let Some((hash, node)) = self.0.as_ref() {
                write!(f, "{} -> ", HashFrag::<H>(hash))?;
                match &node.kind {
                    Kind::Leaf { value, .. } => {
                        write!(f, "L({}, {:?})", to_bin::<false>(&node.key), value)
                    }
                    Kind::Branch { mask, children, .. } => {
                        write!(f, "B({}, {}, ", to_bin::<false>(&node.key), to_bin::<false>(&[*mask]))?;
                        for (idx, child) in children.iter().enumerate() {
                            write!(f, "\n")?;
                            Self::debug_fmt(&child, depth+1, Some(idx), f)?;
                        }
                        write!(f, "\n{})", space)
                    }
                    Kind::Opaque(..) => write!(f, "O({})", HashFrag::<H>(hash))
                }
            } else {
                if depth == 0 {
                    write!(f, "Trie(Empty)")
                } else {
                    write!(f, "E")
                }
            }
        }
    }

    /// The digest of a Merkle trie is just the digest of its root hash
    impl<T: Digestible, const N: usize, const K: usize, H:Digest, A: Allocator + Clone, M: TrieMode> Digestible for Trie<T,N,K,H,A,M> {
        fn update_hasher<D: Digest>(&self, hasher: &mut D) {
            hasher.update(self.digest());
        }
    }
}