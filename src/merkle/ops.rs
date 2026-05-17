/// Defines the Merkle Trie operations

use std::fmt::Debug;

use digest::{Digest, Output};

use crate::digestible::Digestible;
use crate::utils::{Allocator, Box};
use crate::unreachable_checked;

use super::data::{Trie, Node, Kind, Concrete, Witness};

fn item() {
    // does nothing
}

impl<T: Debug + Digestible, const N: usize, const K: usize, A: Allocator + Clone + Debug, H: Digest> Node<T,N,K,A,H,Concrete> {
    fn value(&self) -> Option<&T> {
        match &self.kind {
            Kind::Branch { .. } => None,
            Kind::Leaf { value, .. } => Some(value),
            Kind::Opaque(never) => unreachable_checked!(never),
        }
    }
}
