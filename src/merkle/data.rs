/// Defines the Merkle Trie type structure

use core::fmt::Debug;
use std::convert::Infallible;

use digest::{Digest, Output};

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

// implement opaque trie node witness type
mod sealed { pub trait Mode {} }

pub struct Concrete;
pub struct Witness;
impl sealed::Mode for Concrete {}
impl sealed::Mode for Witness {}

pub trait TrieMode: sealed::Mode {
    type Witness<H: Digest>: Clone;
}

impl TrieMode for Concrete {
    type Witness<H: Digest> = Infallible;
}

impl TrieMode for Witness {
    type Witness<H: Digest> = Output<H>;
}