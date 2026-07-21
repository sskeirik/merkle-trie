## Introduction

A generic, Merkleized, compressed Trie library.

Expanding upon the summary sentence in more detail, we have:

1. _Trie_- A kind of K-ary tree such that:

   1. node keys are sequences of atoms (i.e., [monoids](https://en.wikipedia.org/wiki/Monoid));
   2. locally, each node only stores a _fragment_ of a key;
   3. the true key of a node is the concatenation of all key fragments along the path from the root to that node.

   In our case, keys are always byte strings (`&[u8]`) of some maximum size.

2. _Compressed_ - Single-child nodes are merged with their parents.

   In particular, this means that Trie branches will always have at least 2 children.
   To merge a unique child node into a parent branch node, on the parent node:

   1. set its key to be the concatenation of both keys;
   2. set its body to be the body of the child node.

3. _Merkleized_ - Each node has a cryptographic digest derived from its stored value and/or its children's digests.

   This means that trie equality can be computed just by comparing trie root hashes (see [`Trie::hash_eq`]).
   Applying this property recursively means that we can represent sub-tries by their root hash,
   enabling an more powerful form of compression when the contents of a particular sub-trie are
   irrelevant for a given operation (see [`Trie::witness_for_keys`]).

4. _Generic_ - The implementation exposes the following user-settable generic parameters:

   | Param | Bounds                    | Description                                                                                |
   | ---   | ---                       | ---                                                                                        |
   | `T`   | [`Digestible`]            | The value type stored in this trie                                                         |
   | `N`   | [`usize`]                 | Max key length in bytes                                                                    |
   | `K`   | [`usize`]                 | Node branching factor (must choose 2,4,16, or 256 - powers of two ensure fast bitwise ops) |
   | `H`   | [`Digest`]                | The hash function used for hash pointers                                                   |
   | `A`   | [`Allocator`] + [`Clone`] | The allocator used to store keys/values/nodes                                              |
   | `M`   | [`TrieMode`]              | Either [`Complete`] or [`Partial`] which enables `Opaque` nodes                            |

   For dense tries, higher branching factors can reduce size overhead.

   If `T` also implements [`Debug`]/[`Clone`], then [`Trie`] implements [`Debug`]/[`Clone`].

## Limitations

For implementation simplicity:

1. Values can only be set on true leaf nodes (setting values on intermediate nodes is unsupported).

## Cargo Features

- `std_allocator_api` - defines `Allocator` as `std::alloc::Allocator` (currently requires nightly Rust); if unset, the `allocator-api2` shim package is used instead.

## Example Code

```rust
use allocator_api2::alloc::Global;
use sha2::Sha256;
use merkle_trie::{Trie,Complete,Digest,Digestible};

#[derive(Clone, Debug)]
struct MyCustomData(u64);
impl Digestible for MyCustomData {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) {
        hasher.update(&self.0.to_le_bytes())
    }
}

type MyTrie = Trie<MyCustomData,4,2,Sha256,Global,Complete>;

let mut t: MyTrie = Trie::new();
t.set(&[1,2,3    ], MyCustomData(45));
t.set(&[1,2,4    ], MyCustomData(78));
t.set(&[1,2,5    ], MyCustomData(127));
let delete_result = t.delete(&[1,2,4]);
match delete_result {
   Ok(v) => println!("Old value at key was {v:?}"),
   Err(e) => println!("Error {e} occurred"),
};
let get_result = t.get(&[1,2,3]);
match get_result {
   Ok(v) => println!("Borrow a value: {v:?}"),
   Err(e) => println!("Error {e} occurred"),
}

// if Trie data supports Clone/Debug, so does Trie
let trie_clone = t.clone();
println!("Trie clone: {trie_clone:?}");

// build witnesses
let mut witness1 = t.clone().to_partial();
witness1.witness_for_keys(vec![&[1,2]]);
println!("Witness 1: {witness1:?}");

let mut witness2 = t.clone().to_partial();
witness2.witness_for_keys(vec![&[1,2,3]]);
println!("Witness 2: {witness2:?}");
``` 

## Details

Internally, we implement core trie operations `get`, `update`, and `delete` as thin wrappers around a pair of shared traversal
routines, `probe` (read-only) and `probe_mut` (mutating).

Each of these routines walks the trie from the root, following the branch matching each key's bits,
until it reaches either an exact match, an empty
child slot, a bounded search limit, or a point of disagreement between the search key and a stored node key
(search for `ProbeResult` to see the details).

Rather than duplicating this walk for every operation, the walk itself is written once, and each
operation instead supplies a closure - an "action" - that is invoked exactly once, at the point where the probe
terminates, with the `ProbeResult` it produced.

This means the operation-specific logic (installing a new leaf/branch on `update`, removing a leaf on `delete`, returning a
value reference on `get`) lives entirely inside the closure passed to `probe`/`probe_mut`, while the shared traversal
code stays agnostic to what the caller intends to do with the result. 

Finally, on the way back up the call-stack,`probe_mut` also re-hashes modified nodes and,
where a branch has been reduced to a single child, compresses the branch-child pair,
so callers only need to describe the change they want made at the point of divergence
rather than managing digest recomputation or trie compression themselves.