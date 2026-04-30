# cenetex/merkle — canonical form specification

This is the load-bearing document. Every verifier — the C reference
implementation in `include/merkle.h`, the Solana program that consumes
inclusion proofs, any future Rust/TypeScript port — must agree on
every byte described below. Drift here = forks in the chain.

This spec is versioned. Breaking changes bump the spec version and
require coordinated updates to every verifier in the network.

**Spec version: 1**

---

## 1. Hash function

The MMR is hash-function-agnostic at the API surface. The implementation
takes a `merkle_hash_pair_fn` callback:

```c
void hash_pair(const uint8_t left[32],
               const uint8_t right[32],
               uint8_t out[32]);
```

The contract: `out = H(left || right)` where `||` is byte concatenation
and `H` is a 32-byte cryptographic hash. All examples and golden vectors
in this repo use **SHA-256** as `H`. Other hash families (Poseidon,
Blake3, etc.) work as long as every verifier in the network agrees on
the choice for a given snapshot.

The hash output is 32 bytes. Hashes wider than 32 bytes are not
supported in v1 of this spec; truncation strategies are out of scope.

## 2. MMR position numbering

Positions are 1-based, depth-first. Leaf 0 sits at position 1; leaf 1
at position 2; the parent of {1, 2} at position 3; leaf 2 at position
4; leaf 3 at position 5; the parent of {4, 5} at position 6; the parent
of {3, 6} at position 7; and so on.

For 8 leaves the array layout is:

```
position:  1  2  3  4  5  6  7  8  9  10 11 12 13 14 15
content:   l0 l1 p  l2 l3 p  P  l4 l5 p  l6 l7 p  p  P*
                  /3\        /7\           /13\       /15
                                                       \    
                                            (P* is root for 8-leaf MMR)
```

This matches Grin's MMR convention. The MMR struct is conceptually a
flat array indexed 1..N (or 0..N-1 internally — implementations choose,
but the **logical** position numbering is 1-based for proof formats).

### Position-to-height arithmetic

For a position `p`, its height in the tree (0 = leaf) is computed by
the standard "all-ones-binary" trick: `p` is a peak when its binary
representation is all ones (so positions 1, 3, 7, 15, 31, ... are peaks
of complete subtrees of height 0, 1, 2, 3, 4 respectively).

`height(p) = popcount(p ^ (p - 1)) - 1` for an "all-ones" trailing
suffix; otherwise walk left until you hit one. The reference
implementation has the canonical version.

### Leaf index ↔ position

```
leaf_index_to_pos(i):
  Given the i-th leaf (0-based), return its 1-based position.
  Closed form: i + popcount(i + 1) where i is 0-based.

  Examples:
    leaf 0 → pos 1
    leaf 1 → pos 2
    leaf 2 → pos 4
    leaf 3 → pos 5
    leaf 4 → pos 8
    leaf 5 → pos 9
    leaf 6 → pos 11
    leaf 7 → pos 12
```

Verifiers compute leaf positions independently from `leaf_idx`; the
position is **not** transmitted in proofs.

## 3. Peak set

After N leaves are appended, the MMR has a set of peaks: the roots of
the maximal complete subtrees. The number of peaks equals
`popcount(N)`; the peak heights, listed left-to-right (largest first),
are the bit positions set in N from MSB to LSB.

**Examples:**

| Leaves N | popcount | Peak heights L→R |
|----------|----------|------------------|
| 1        | 1        | [0]              |
| 2        | 1        | [1]              |
| 3        | 2        | [1, 0]           |
| 4        | 1        | [2]              |
| 5        | 2        | [2, 0]           |
| 7        | 3        | [2, 1, 0]        |
| 8        | 1        | [3]              |
| 11       | 3        | [3, 1, 0]        |

`peak_idx` in the proof is the **left-to-right** index of the leaf's
peak (0 = leftmost). For 11 leaves, leaf 3 is under peak 0 (height 3,
covering leaves 0..7); leaf 8 is under peak 1 (height 1, covering 8..9);
leaf 10 is under peak 2 (height 0, the singleton).

## 4. Inclusion proof format

A proof for the i-th leaf consists of:

- The 32-byte hashes of every sibling on the path from the leaf to its
  peak, **bottom-up** (leaf's sibling first, peak's child last).
- The peaks **other than the leaf's own peak**, in left-to-right order,
  appended after the path siblings.

The path siblings count is `peak_height` (the height of the leaf's
peak); the peak count appended is `total_peaks - 1`. So the total proof
length is `peak_height + (total_peaks - 1)` 32-byte hashes.

**Calldata layout** (what gets posted on-chain or sent to a verifier):

```
leaf_hash:        32 bytes
leaf_idx:         8 bytes  little-endian uint64
leaf_count:       8 bytes  little-endian uint64    (N at snapshot time)
peak_idx:         8 bytes  little-endian uint64    (leaf's peak L→R)
proof_len:        8 bytes  little-endian uint64
proof_hashes:     proof_len * 32 bytes
```

All multi-byte integers are little-endian. The on-disk anchor format
(spec'd separately by the consumer) wraps this with a signature; this
spec is only the proof bytes.

## 5. Root computation

The MMR root is computed by:

1. Computing each peak's hash (each peak is the root of a complete
   binary tree, computed bottom-up by hashing children pairwise).
2. **Right-fold bagging**: given peaks `[P_0, P_1, ..., P_{k-1}]` in
   left-to-right order:

```
if k == 1:
    root = P_0
else:
    acc = P_{k-1}
    for i in [k-2, k-3, ..., 0]:
        acc = H(P_i || acc)
    root = acc
```

Equivalently: `root = H(P_0, H(P_1, H(P_2, ... H(P_{k-2}, P_{k-1}) ...)))`.

**Leaf count is NOT folded into any hash.** Some MMR implementations
(Grin v2+) include the leaf count as an explicit input to the bagging
step to prevent length-extension games across snapshots. This spec
explicitly does not — the consumer (e.g. a Solana program verifying
"rock X was destroyed before epoch N") is expected to receive
`leaf_count` as separate calldata and use it to validate the proof
shape, not to recompute the root.

The rationale: keeping leaves count out of the hash means proofs are
format-identical regardless of which snapshot is being referenced, and
the on-chain anchor commits to (root, leaf_count, signature) as a
tuple anyway, so a length-extension attack would have to forge the
signature, not the root.

## 6. Verification algorithm

Given `(leaf, leaf_idx, leaf_count, peak_idx, proof[], expected_root)`:

1. Compute `pos = leaf_index_to_pos(leaf_idx)`.
2. Compute `peak_heights = peaks_for_count(leaf_count)`.
3. Verify `peak_idx < len(peak_heights)`. If not, reject.
4. `peak_height = peak_heights[peak_idx]`.
5. Verify `proof_len == peak_height + (len(peak_heights) - 1)`. If not, reject.
6. Climb the peak: walk up `peak_height` levels, hashing each step
   with the next proof entry. Whether the proof entry goes left or
   right of the accumulator is determined by the parity of the
   current height's local index. Result: the leaf's peak hash.
7. Bag the peaks: replace `peak_heights[peak_idx]` with the value
   computed in step 6, then right-fold all peaks per §5.
8. Compare to `expected_root`. Equal → accept; else reject.

The reference C implementation has the canonical version; any spec
ambiguity is resolved by reading `merkle.h`.

## 7. Forbidden operations

This is an append-only structure. The following are not in the spec:

- Leaf deletion or modification.
- Insertion at arbitrary positions.
- Rolling back to a prior leaf count.

Snapshots are taken by recording the root + leaf count at a point in
time. The MMR continues growing past the snapshot; verifiers prove
inclusion against the *snapshot's* root, not the live root.

## 8. Versioning policy

- **Patch (1.0.x)**: bug fixes that don't change byte output for any
  input. Verifiers using v1.0.0 and v1.0.5 produce bit-identical
  outputs.
- **Minor (1.x.0)**: API additions that don't change byte output for
  inputs accepted by both versions.
- **Major (x.0.0)**: any change that produces different byte output
  for the same input. Requires a coordinated upgrade across every
  verifier in the network.

The current spec version is encoded as `MERKLE_SPEC_VERSION = 1` in
`merkle.h`. Implementations check this at compile time.
