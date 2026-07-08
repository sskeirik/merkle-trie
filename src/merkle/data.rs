/// Defines the Merkle Trie type structure

use std::convert::Infallible;

use digest::{Digest, Output};

use crate::digestible::Digestible;
use crate::utils::{Allocator, Box};

/// A generic Merkle trie that is either fully concrete or possibly partial
#[derive(Clone)]
pub struct Trie<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode>(pub(crate) A, pub(crate) Option<(Output<H>, Node<T,N,K,A,H,M>)>);

/// A generic Merkle trie node
 #[derive(Clone)]
 #[repr(C)]
pub(crate) struct Node<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> {
    /// the whole bytes that must be matched to visit this node
    pub(crate) key: Box<[u8],A>,
    /// the node's kind-specific data
    pub(crate) kind: Kind<T,N,K,A,H,M>,
}

#[derive(Clone)]
#[repr(C)]
pub(crate) struct BranchData<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> {
    /// defines which log2(K) bits in the (key.len())th byte distinguish children of this branch
    pub mask: u8,
    /// the children of this branch
    pub children: [Option<HashNode<T,N,K,A,H,M>>; K],
}

/// A generic Merkle trie node payload
#[derive(Clone)]
#[repr(C, u8)]
pub(crate) enum Kind<T: Digestible, const N: usize, const K: usize, A: Allocator + Clone, H: Digest, M: TrieMode> {
    /// A trie branch
    Branch(BranchData<T,N,K,A,H,M>),
    /// A trie leaf
    Leaf {
        /// the data stored at this leaf
        value: T,
        /// zero-sized type that exists to record the hash algorithm used by this trie
        _phantom: std::marker::PhantomData<H>,
    },
    /// Witness for a subtrie of unknown shape; not available in concrete tries.
    /// The mode `M::Marker` is a zero-sized tag that is uninhabited for `Concrete`
    /// (making this variant unconstructible there) and `()` for `Witness`. Note
    /// that this variant's size does not depend on this marker, which means that
    /// the layout can be made idenical across modes.
    Opaque(Output<H>, M::Marker),
}

// A pair of a boxed node and its hash
pub(crate) type HashNode<T, const N: usize, const K: usize, A, H, M> = (Output<H>, Box<Node<T,N,K,A,H,M>, A>);

/// Trait that describes how to update values in a Node.
pub trait NodeUpdate<V> {
    /// a function that can update the value if it already exists.
    fn on_occupied(self, val: &mut V);
    /// returns the value to insert if no value is present;
    /// None means that no value will be inserted
    fn on_vacant(self) -> Option<V>;
}
// Some notes:
// 
// 1. This works better than passing an option<V> and FnOnce(&mut V) 
//    to the update function because the value _V_ in both cases can 
//    _share_ memory if desired.
// 2. We alternatively might make `on_occupied` take a `FnOnce(&mut V)`;
//    this permits callers to pass in a custom update function without
//    needing to reimplement the trait; but this is an illusion, we can
//    create a trait impl, once an for all, which takes this
//    closure/function and routes our &mut into it.
//    However, in general, having a closure for the update case means
//    that we cannot safely share memory with the vacant case.

pub struct SimpleUpdate<V>(pub V);

impl<V> NodeUpdate<V> for SimpleUpdate<V> {
    fn on_occupied(self, val: &mut V) {
        *val = self.0;
    }

    fn on_vacant(self) -> Option<V> {
        Some(self.0)
    }
}

// implement opaque trie node partial type
mod sealed { pub trait Mode {} }

#[derive(Clone)]
pub struct Concrete;
#[derive(Clone)]
pub struct Partial;
impl sealed::Mode for Concrete {}
impl sealed::Mode for Partial {}

pub trait TrieMode: sealed::Mode {
    /// Zero-sized tag for `Kind::Opaque`: uninhabited for `Concrete` (so the
    /// variant can never be constructed), `()` for `Witness`.
    type Marker: Clone;
}

impl TrieMode for Concrete {
    type Marker = Infallible;
}

impl TrieMode for Partial {
    type Marker = ();
}