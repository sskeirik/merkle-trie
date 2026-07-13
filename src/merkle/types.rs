/// Defines the Merkle Trie type structure
use digest::{Digest, Output};

use crate::digestible::Digestible;
use crate::utils::{Allocator, Box};

/// A generic, compressed Merkleized trie.
/// 
/// We describe its generic paramters below:
/// 
/// | Param | Bounds                                                               | Description                                                             |
/// | ---   | ---                                                                  | ---                                                                     |
/// | `T`   | [`Digestible`]                                                       | The value type stored in this trie                                      |
/// | `N`   | [`usize`]                                                            | Max key length in bytes                                                 |
/// | `K`   | [`usize`]                                                            | Node branching factor (2,4,16,256 - powers of two for fast bitwise ops) |
/// | `H`   | [`Digest`]                                                           | The hash function used for hash pointers                                |
/// | `A`   | [`Allocator`] + [`Clone`]                                             | The allocator used to store keys/values/nodes                           | 
///
/// For dense tries, higher branching factors can reduce size overhead.
///
/// If `T` also implements [`Debug`]/[`Clone`], then [`Trie`] will implements [`Debug`]/[`Clone`].
#[derive(Clone)]
pub struct Trie<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode>(pub(crate) A, pub(crate) NodeLink<T,N,K,A,H,M>);

/// A node in a Merkleized, compressed trie.
/// 
/// The `repr(C)` attribute ensures a consistent representation across the distinct [`TrieMode`]s
/// 
/// This type is made public for documentation purposes, but since
/// the [`Trie`] internals are private, it cannot be directly used
/// for [`Trie`] introspection.
 #[derive(Clone)]
 #[repr(C)]
pub struct Node<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> {
    /// the whole bytes that must be matched to visit this node
    pub key: Box<[u8],A>,
    /// the node's kind-specific data
    pub kind: Kind<T,N,K,A,H,M>,
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
pub enum Kind<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> {
    /// A trie branch
    Branch {
        /// Encodes the log2(`K`) bits in the [`Node::key`]`.len()`th byte that distinguishes the keys of child nodes
        mask: u8,
        /// Stores the `K` child nodes of this branch
        children: [NodeLink<T,N,K,A,H,M>; K],
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
pub type NodeLinkRef<T,const N: usize, const K: usize, A, H, M> = (Output<H>, Box<Node<T,N,K,A,H,M>, A>);

/// A nullable link between [`Node`]s in a [`Trie`]
#[derive(Clone)]
pub struct NodeLink<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode>(
    pub Option<NodeLinkRef<T,N,K,A,H,M>>,
);

// implement opaque trie node partial type
mod sealed { pub trait SealedTrieMode {} }
pub use mode::{Complete, Partial};
pub mod mode {
    #[allow(unused_imports)] // for doc-comments
    use super::{Trie, Kind};
    /// Marker type that forces a [`Trie`] to be complete (i.e., it _cannot_ contain [`Kind::Opaque`] nodes).
    #[derive(Clone)]
    pub struct Complete;
    /// Marker type that permits a [`Trie`] to be partial (i.e., it _may_ contain [`Kind::Opaque`] nodes).
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


/// Trait that describes how to update the value stored in a [Node].
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
pub struct NodeUpsert<T> {
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
