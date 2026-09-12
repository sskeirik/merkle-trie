> ⚠️ **Beta Software**  
> This project has a largely stable design and feature set, but needs more testing and refinement.  
> The API is not expected to change significantly unless bugs are encountered.  
> Not recommended for production use.

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

   Note that this is a form of _lossless compression_ (and is _distinct_ from what we will discuss immediately below).

3. _Merkleized_ - Each node has a cryptographic digest derived from its stored value and/or its children's digests.

   Applying this property recursively means that we can represent entrie sub-tries by their root hash,
   enabling a powerful form of _lossy_ compression where, when the contents of a particular sub-trie are
   irrelevant for a given operation, we can replace that sub-trie by a stub containing just its root hash
   (see [`Trie::witness_for_keys`]).

   Taken to the limit, if we only care about trie identity (i.e., _all_ stored is irrelevant), we can
   collapse the entire trie into just its root's digest and use that to peform equality checks
   (see [`Trie::hash_eq`]).

   In particular, the [`TrieMode`] parameter ensures that this kind of lossy compression
   is _disabled by default_ and attempting to use is a _type error_; to enable it, call
   [`Trie::to_parial`].

4. _Generic_ - The implementation exposes the following user-settable generic parameters:

   | Param | Bounds                    | Description                                                                                |
   | ---   | ---                       | ---                                                                                        |
   | `T`   | [`Digestible`]            | The value type stored in this trie                                                         |
   | `N`   | [`usize`]                 | Max key length in bytes                                                                    |
   | `K`   | [`usize`]                 | Node branching factor (must choose 2,4,16, or 256 - powers of two ensure fast bitwise ops) |
   | `H`   | [`Digest`]                | The hash function used for hash pointers                                                   |
   | `A`   | [`Allocator`] + [`Clone`] | The allocator used to store keys/values/nodes                                              |
   | `M`   | [`TrieMode`]              | Either [`Complete`] or [`Partial`] which enables `Opaque` nodes and compression            |

   For dense tries, higher branching factors can reduce size overhead.

   If `T` also implements [`Clone`], then [`Trie`] implements [`Clone`].
   Note that [`Trie`] has a fallback [`Debug`] implementation which is active whenever `T: !Debug`;
   however, a specialized [`Debug`] implementation is available when `T: Debug`.

## Limitations

For implementation simplicity:

1. Values can only be set on true leaf nodes (setting values on intermediate nodes is unsupported).

## Cargo Features

- `std_allocator_api` - defines `Allocator` as `std::alloc::Allocator` (currently requires nightly Rust); if unset, the `allocator-api2` shim package is used instead.

## Example Code

```rust
use {merkle_trie::{Trie,Complete,Digest,Digestible,utils::Global}, sha2::Sha256};

#[derive(Clone, Debug)]
struct Data(u64);
impl Digestible for Data {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) { hasher.update(&self.0.to_le_bytes()) }
}
type MyTrie = Trie<Data,4,2,Sha256,Global,Complete>;

let mut t: MyTrie = Trie::new();
t.set(&[1,2,3], Data(45));
t.set(&[1,2,4], Data(78));
t.set(&[1,2,5], Data(127));
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
// NOTE: these construction techniques require `T: Clone`
// as the witness tries may actually contain the underlying
// trie values on leaf nodes
let witness1 = t.to_witness_for_keys(vec![&[1,2,3]]);
println!("Witness 1: {witness1:?}");

let mut witness2 = t.clone().to_partial();
witness2.prune_for_keys(vec![&[1,2]]);
println!("Witness 2: {witness2:?}");

// verify witnesses
let keys: Vec<&[u8]> = vec![&[1,2,3], &[1,2,4], &[1,2,5]];
let expected = vec![Some(true), Some(false), None];
assert_eq!(witness1.verify_keys(&keys, &expected), true);

let expected = vec![None, Some(false), None];
assert_eq!(witness2.verify_keys(keys, expected), true);
```

`to_witness_for_keys` and cloning the [`Trie`] itself both require `T: Clone`,
since the resulting witness may actually retain the original leaf values. When
`T` is not `Clone`, use `to_hash_witness_for_keys` instead: it builds a witness
that represents any leaf value outside the witness by its digest rather than
by cloning it.

```rust
use {merkle_trie::{Trie,Complete,Digest,Digestible,utils::Global}, sha2::Sha256};

// note: no `Clone` impl/derive here
#[derive(Debug)]
struct NonCloneData(u64);
impl Digestible for NonCloneData {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) { hasher.update(&self.0.to_le_bytes()) }
}
type NonCloneTrie = Trie<NonCloneData,4,2,Sha256,Global,Complete>;

let mut t: NonCloneTrie = Trie::new();
t.set(&[1,2,3], NonCloneData(45));
t.set(&[1,2,4], NonCloneData(78));
t.set(&[1,2,5], NonCloneData(127));

// `t.clone()` and `t.to_witness_for_keys(..)` would both fail to compile here,
// since `NonCloneData` does not implement `Clone`.
let keys: Vec<&[u8]> = vec![&[1,2,3], &[1,2,4], &[1,2,5]];
let witness = t.to_hash_witness_for_keys(keys.clone());
println!("Hash witness: {witness:?}");

let expected = vec![Some(true); keys.len()];
assert_eq!(witness.verify_keys(&keys, &expected), true);
```

But, calling `prune_for_keys` on a [`Complete`] Trie is a type-error:

```rust,compile_fail
use {merkle_trie::{Trie,Complete,Digest,Digestible,utils::Global}, sha2::Sha256};

#[derive(Clone, Debug)]
struct Data(u64);
impl Digestible for Data {
    fn update_hasher<D: Digest>(&self, hasher: &mut D) { hasher.update(&self.0.to_le_bytes()) }
}
type MyTrie = Trie<Data,4,2,Sha256,Global,Complete>;

let mut t: MyTrie = Trie::new();
t.set(&[1,2,3], Data(45));

// TYPE-ERROR: Calling partial-only operation on complete trie!
t.prune_for_keys(vec![&[1,2,3]]);
```

## Details

Internally, we implement core trie operations `get`, `update`, and `delete` as thin wrappers around a pair of shared traversal
routines, `probe` (read-only) and `probe_mut` (mutating).

Each traversal routine walks the trie from the root, following the branch matching each key's bits, until it reaches either:
an exact match, an empty child slot, a bounded search limit, or a disagreeing bit between the target key and a stored node key
(search for `ProbeResult` to see the details).

The core trie operations then just invoke the probe routine with an "action" closure, invoked at the point where the probe terminates,
that consumes the `ProbeResult` in order to perform its requested operation.

This means the operation-specific logic (installing a new leaf/branch on `update`, removing a leaf on `delete`, returning a
value reference on `get`) lives entirely inside the closure passed to `probe`/`probe_mut`, while the shared traversal
code stays agnostic to what the caller intends to do with the result.

Finally, on the way back up the call-stack,`probe_mut` also re-hashes modified nodes and,
where a branch has been reduced to a single child, compresses the branch-child pair,
so callers only need to describe the change they want made at the point of divergence
rather than managing digest recomputation or trie compression themselves.
