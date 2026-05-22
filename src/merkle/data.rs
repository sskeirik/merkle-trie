/// Defines the Merkle Trie type structure

use core::fmt::Debug;
use std::convert::Infallible;

use digest::{Digest, Output};

use crate::unreachable_checked;
use crate::digestible::Digestible;
use crate::utils::{Allocator, Box};

 /// A generic Merkle trie
 #[derive(Clone)]
pub struct Trie<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest, M: TrieMode>(pub(crate) Option<(Output<H>, Node<T,N,K,A,H,M>)>);

 /// A generic Merkle trie node
 #[derive(Clone)]
pub struct Node<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest, M: TrieMode> {
    /// the whole bytes that must be matched to visit this node
    pub(crate) key: Box<[u8],A>,
    /// the node's kind-specific data
    pub(crate) kind: Kind<T,N,K,A,H,M>,
}

 /// A generic Merkle trie node payload
#[derive(Clone)]
pub enum Kind<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest, M: TrieMode> {
    /// A trie branch
    Branch {
        /// defines which log2(K) bits in the (key.len())th byte distinguish children of this branch
        mask: u8,
        /// the children of this branch
        children: [Option<HashNode<T,N,K,A,H,M>>; K],
    },
    /// A trie leaf
    Leaf {
        /// the data stored at this leaf
        value: T,
        /// zero-sized type that exists to record the hash algorithm used by this trie
        _phantom: std::marker::PhantomData<H>,
    },
    /// Witness for a subtrie of unknown shape; not available in concrete tries
    Opaque(M::Witness<H>),
}

// A pair of a boxed node and its hash
pub type HashNode<T, const N: usize, const K: usize, A, H, O> = (Output<H>, Box<Node<T,N,K,A,H,O>, A>);

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

// implement opaque trie node witness type
mod sealed { pub trait Mode {} }

pub struct Concrete;
pub struct Witness;
impl sealed::Mode for Concrete {}
impl sealed::Mode for Witness {}

pub trait TrieMode: sealed::Mode {
    type Witness<H: Digest>: Clone;
    fn digest_opaque<H: Digest>(witness: &Self::Witness<H>) -> Option<Output<H>>;
}

impl TrieMode for Concrete {
    type Witness<H: Digest> = Infallible;
    fn digest_opaque<H: Digest>(never: &Self::Witness<H>) -> Option<Output<H>> {
        unreachable_checked!(never)
    }
}

impl TrieMode for Witness {
    type Witness<H: Digest> = Output<H>;
    fn digest_opaque<H: Digest>(digest: &Self::Witness<H>) -> Option<Output<H>> {
        Some(digest.clone())
    }
}