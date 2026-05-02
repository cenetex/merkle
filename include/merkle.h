/*
 * cenetex/merkle — Merkle Mountain Range, single-header C
 *
 * SPDX-License-Identifier: MIT-0
 *
 * Spec: SPEC.md (canonical-form contract). Read it before changing
 * anything in this file. Drift here = forks in any chain that anchors
 * roots produced by this implementation.
 *
 * Usage:
 *   In exactly one .c file:
 *     #define MERKLE_IMPL
 *     #include "merkle.h"
 *   Everywhere else: just #include "merkle.h".
 *
 * Hash function is caller-supplied via merkle_hash_pair_fn so the same
 * primitive serves SHA-256, Poseidon, Blake3, etc. without forks. The
 * canonical bytes hashed are exactly `left[32] || right[32]`; if you
 * need domain separation, do it inside your own hash callback.
 *
 * Storage model: caller-owned. merkle_mmr_new() malloc()s a parallel
 * dynamic array of {32-byte hash, 1-byte height} per node and grows it
 * on append. Storing height directly avoids the fiddly position-to-
 * height arithmetic and makes the implementation small enough to read
 * end-to-end.
 */

#ifndef CENETEX_MERKLE_H
#define CENETEX_MERKLE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define MERKLE_SPEC_VERSION 1

/* Maximum proof length in 32-byte hashes. Covers up to 2^64 leaves
 * (path height <= 63, peak count <= 64). 128 hashes is generous. */
#define MERKLE_MMR_MAX_PROOF_LEN 128

typedef void (*merkle_hash_pair_fn)(const uint8_t left[32],
                                     const uint8_t right[32],
                                     uint8_t out[32]);

typedef struct merkle_mmr merkle_mmr_t;

/* Construction / destruction. */
merkle_mmr_t *merkle_mmr_new(merkle_hash_pair_fn hash_pair);
void          merkle_mmr_free(merkle_mmr_t *m);

/* Append a leaf. Returns the 1-based MMR position of the leaf node. */
size_t        merkle_mmr_append(merkle_mmr_t *m, const uint8_t leaf[32]);

/* Number of leaves (zero-based count of leaves appended so far). */
size_t        merkle_mmr_leaf_count(const merkle_mmr_t *m);

/* Total nodes in the underlying array (leaves + internal). */
size_t        merkle_mmr_node_count(const merkle_mmr_t *m);

/* Compute the current root into out[32]. SPEC.md §5 (right-fold).
 * Writes 32 zero bytes when leaf_count == 0; callers must check
 * leaf_count separately before treating the root as meaningful. */
void          merkle_mmr_root(const merkle_mmr_t *m, uint8_t out[32]);

/* Build an inclusion proof for the given 0-based leaf index.
 * Returns proof length in 32-byte hashes, or -1 on error.
 * Writes the leaf's peak index (left-to-right, 0-based) into *out_peak. */
int  merkle_mmr_proof(const merkle_mmr_t *m, size_t leaf_idx,
                      uint8_t proof_out[MERKLE_MMR_MAX_PROOF_LEN][32],
                      size_t *out_peak);

/* Stateless verifier — mirror this in your on-chain program. The
 * hash callback must agree with the producer. SPEC.md §6. */
bool merkle_mmr_verify(merkle_hash_pair_fn hash_pair,
                       const uint8_t leaf[32],
                       size_t leaf_idx,
                       const uint8_t (*proof)[32],
                       size_t proof_len,
                       size_t peak_idx,
                       size_t leaf_count,
                       const uint8_t expected_root[32]);

/* Helpers exposed for advanced users (verifier shims, golden-vector
 * tests). All match SPEC.md §2-3. */

/* Convert 0-based leaf index to 1-based MMR position. Closed form:
 *   pos = 2*leaf_idx + 1 - popcount(leaf_idx)
 * Derivation: leaf i is preceded by i other leaves and (i - popcount(i))
 * internal nodes, plus its own slot (1-based offset).
 *
 * Note: the 2*leaf_idx term overflows uint64_t once leaf_idx >= 2^63,
 * so this function (and any MMR built with it) is well-defined only
 * for leaf_idx < 2^63. Practically unreachable but documented here
 * so callers don't rely on the MERKLE_MMR_MAX_PROOF_LEN comment's
 * "2^64 leaves" upper bound. */
size_t merkle_leaf_index_to_pos(uint64_t leaf_idx);

/* Number of peaks for a given leaf count = popcount(leaf_count). */
size_t merkle_peak_count(uint64_t leaf_count);

/* Fill `out` with peak heights left-to-right (largest first).
 * Returns the number written. `out` should hold at least 64 entries. */
size_t merkle_peak_heights(uint64_t leaf_count, uint8_t out[64]);

#ifdef __cplusplus
}
#endif

/* ===================================================================
 * Implementation. Define MERKLE_IMPL in exactly one TU.
 * =================================================================== */

#ifdef MERKLE_IMPL

#include <assert.h>
#include <stdlib.h>
#include <string.h>

struct merkle_mmr {
    merkle_hash_pair_fn hash_pair;
    uint8_t (*nodes)[32];   /* index 0 = MMR pos 1 (1-based logically) */
    uint8_t  *heights;       /* parallel array; heights[i] = node at pos i+1 */
    size_t    node_count;
    size_t    capacity;
    uint64_t  leaf_count;
};

/* --- popcount fallback ----------------------------------------- */

static inline int merkle__popcount64(uint64_t x) {
#if defined(__GNUC__) || defined(__clang__)
    return __builtin_popcountll((unsigned long long)x);
#else
    int n = 0;
    while (x) { n += (int)(x & 1u); x >>= 1; }
    return n;
#endif
}

/* --- SPEC §2: closed-form leaf-index to 1-based MMR position --- */

size_t merkle_leaf_index_to_pos(uint64_t leaf_idx) {
    /* Position of leaf i (0-based) = 2*i + 1 - popcount(i).
     * Sanity check (leaf, pos): (0,1) (1,2) (2,4) (3,5) (4,8) (5,9)
     *                            (6,11) (7,12) (8,16) (9,17). */
    return (size_t)(2u * leaf_idx + 1u - (uint64_t)merkle__popcount64(leaf_idx));
}

size_t merkle_peak_count(uint64_t leaf_count) {
    return (size_t)merkle__popcount64(leaf_count);
}

size_t merkle_peak_heights(uint64_t leaf_count, uint8_t out[64]) {
    /* Heights left-to-right (largest first) = bit positions set in
     * leaf_count from MSB to LSB. */
    size_t n = 0;
    for (int b = 63; b >= 0; b--) {
        if ((leaf_count >> b) & 1u) {
            out[n++] = (uint8_t)b;
        }
    }
    return n;
}

/* Emit the 1-based positions of all peaks in left-to-right order
 * (largest height first). Returns the count written. `out` must hold
 * at least 64 entries.
 *
 * Each peak of height h ends at the cumulative-end-of-its-subtree mark,
 * the running sum of (2^(h+1) - 1) over peaks already counted. Doing
 * this in a single forward pass replaces the O(pcount × 64) cost of
 * calling a per-peak position helper from inside root/proof. */
static size_t merkle__peak_positions(uint64_t leaf_count, uint64_t out[64]) {
    size_t n = 0;
    uint64_t cursor = 0;
    for (int b = 63; b >= 0; b--) {
        if (((leaf_count >> b) & 1u) == 0u) continue;
        cursor += ((uint64_t)1 << (b + 1)) - 1;
        out[n++] = cursor;
    }
    return n;
}

/* --- Public API: lifecycle -------------------------------------- */

merkle_mmr_t *merkle_mmr_new(merkle_hash_pair_fn hash_pair) {
    if (!hash_pair) return NULL;
    merkle_mmr_t *m = (merkle_mmr_t *)calloc(1, sizeof(*m));
    if (!m) return NULL;
    m->hash_pair = hash_pair;
    return m;
}

void merkle_mmr_free(merkle_mmr_t *m) {
    if (!m) return;
    free(m->nodes);
    free(m->heights);
    free(m);
}

size_t merkle_mmr_leaf_count(const merkle_mmr_t *m) {
    return m ? (size_t)m->leaf_count : 0;
}

size_t merkle_mmr_node_count(const merkle_mmr_t *m) {
    return m ? m->node_count : 0;
}

/* Grow both parallel arrays. Commits pointers and capacity only after
 * both reallocs succeed, so a partial failure leaves the bookkeeping
 * consistent (capacity always describes the smaller of the two). */
static bool merkle__reserve(merkle_mmr_t *m, size_t need) {
    if (m->capacity >= need) return true;
    size_t cap = m->capacity ? m->capacity : 32;
    while (cap < need) cap *= 2;
    void *new_nodes = realloc(m->nodes, cap * 32);
    if (!new_nodes) return false;
    /* The nodes buffer may have been moved by realloc; we have to adopt
     * the new pointer regardless of whether the heights realloc succeeds,
     * otherwise we'd leak the resized buffer. capacity stays at the old
     * value until both sides are grown. */
    m->nodes = (uint8_t (*)[32])new_nodes;
    void *new_heights = realloc(m->heights, cap);
    if (!new_heights) return false;
    m->heights = (uint8_t *)new_heights;
    m->capacity = cap;
    return true;
}

/* --- Public API: append + root ---------------------------------- */

size_t merkle_mmr_append(merkle_mmr_t *m, const uint8_t leaf[32]) {
    if (!m || !leaf) return 0;
    /* Reserve the worst case up front so the carry loop can't fail
     * partway through and leave the MMR in a torn state (leaf_count
     * bumped but parent nodes not emitted). After this append, the
     * carry depth is at most the number of trailing ones in the new
     * leaf_count, which is bounded by 63 for a 64-bit count, so
     * reserving node_count + 64 covers any append. */
    if (!merkle__reserve(m, m->node_count + 64)) return 0;
    size_t leaf_node_idx = m->node_count;       /* 0-based */
    memcpy(m->nodes[leaf_node_idx], leaf, 32);
    m->heights[leaf_node_idx] = 0;
    m->node_count++;
    m->leaf_count++;

    /* Walk up: while the previous-at-this-height node is a sibling
     * waiting for a parent, hash and emit. The classic "carry" loop:
     * after appending leaf K, we keep merging while the new node's
     * height equals the height of the node immediately to its left
     * (which would be its sibling). */
    while (m->node_count >= 2) {
        size_t right = m->node_count - 1;
        uint8_t h = m->heights[right];
        /* The left sibling of a node at height h sits at index
         * `right - ((1 << (h+1)) - 1)`. If both have the same height,
         * we can merge them into a parent at height h+1. */
        uint64_t span = ((uint64_t)1 << (h + 1)) - 1;
        if ((uint64_t)right < span) break;
        size_t left = right - (size_t)span;
        if (m->heights[left] != h) break;
        /* Capacity was reserved up front; this slot is guaranteed. */
        m->hash_pair(m->nodes[left], m->nodes[right],
                     m->nodes[m->node_count]);
        m->heights[m->node_count] = (uint8_t)(h + 1);
        m->node_count++;
    }
    /* 1-based position of the leaf we just appended. */
    return leaf_node_idx + 1;
}

void merkle_mmr_root(const merkle_mmr_t *m, uint8_t out[32]) {
    if (!m || !out) return;
    if (m->leaf_count == 0) {
        memset(out, 0, 32);
        return;
    }
    uint64_t pos[64];
    size_t pcount = merkle__peak_positions(m->leaf_count, pos);
    if (pcount == 1) {
        memcpy(out, m->nodes[pos[0] - 1], 32);
        return;
    }
    /* Right-fold bag: H(P_0, H(P_1, ... H(P_{k-2}, P_{k-1}))) */
    uint8_t acc[32];
    memcpy(acc, m->nodes[pos[pcount - 1] - 1], 32);
    for (size_t i = pcount - 1; i > 0; i--) {
        uint8_t tmp[32];
        m->hash_pair(m->nodes[pos[i - 1] - 1], acc, tmp);
        memcpy(acc, tmp, 32);
    }
    memcpy(out, acc, 32);
}

/* --- Inclusion proof construction ------------------------------ */

/* Walk leaf_idx up to its peak through the producer's stored array.
 * Each step records the sibling hash; when no same-height sibling
 * exists, the current node is a peak — its 1-based position is used
 * to identify which peak (left-to-right) the leaf belongs to. */
int merkle_mmr_proof(const merkle_mmr_t *m, size_t leaf_idx,
                     uint8_t proof_out[MERKLE_MMR_MAX_PROOF_LEN][32],
                     size_t *out_peak) {
    if (!m || !proof_out) return -1;
    if (leaf_idx >= m->leaf_count) return -1;

    /* Convert leaf index to 0-based array position. */
    size_t pos = (size_t)merkle_leaf_index_to_pos((uint64_t)leaf_idx) - 1;

    size_t off = 0;
    while (1) {
        uint8_t h = m->heights[pos];
        /* Try right-sibling: if there's a same-height node at
         * pos + (2^(h+1) - 1), we are a left child; sibling is to the
         * right. Parent sits at sibling + 1. */
        uint64_t span = ((uint64_t)1 << (h + 1)) - 1;
        size_t right_sib = pos + (size_t)span;
        if (right_sib < m->node_count && m->heights[right_sib] == h) {
            if (off >= MERKLE_MMR_MAX_PROOF_LEN) return -1;
            memcpy(proof_out[off++], m->nodes[right_sib], 32);
            pos = right_sib + 1; /* parent's array slot is right-sibling+1 */
            continue;
        }
        /* Otherwise try left-sibling (we are a right child). Parent's
         * array slot is our slot + 1 (the merger emitted us, then the
         * parent). */
        if (pos >= span) {
            size_t left_sib = pos - (size_t)span;
            if (m->heights[left_sib] == h) {
                if (off >= MERKLE_MMR_MAX_PROOF_LEN) return -1;
                memcpy(proof_out[off++], m->nodes[left_sib], 32);
                pos = pos + 1;
                continue;
            }
        }
        /* No sibling at this height → we are a peak. */
        break;
    }

    /* Single bit-walk over leaf_count: emit every other peak's hash
     * left-to-right, and identify the leaf's own peak by matching its
     * 1-based position against the running cumulative endpoint. */
    uint64_t leaf_peak_pos = (uint64_t)pos + 1;
    uint64_t pp[64];
    size_t pcount = merkle__peak_positions(m->leaf_count, pp);
    size_t peak_idx = (size_t)-1;
    for (size_t k = 0; k < pcount; k++) {
        if (pp[k] == leaf_peak_pos) {
            peak_idx = k;
            continue;
        }
        if (off >= MERKLE_MMR_MAX_PROOF_LEN) return -1;
        memcpy(proof_out[off++], m->nodes[pp[k] - 1], 32);
    }
    if (peak_idx == (size_t)-1) return -1;  /* climb stopped at a non-peak */
    if (out_peak) *out_peak = peak_idx;
    return (int)off;
}

/* --- Stateless verifier ---------------------------------------- */

bool merkle_mmr_verify(merkle_hash_pair_fn hash_pair,
                       const uint8_t leaf[32],
                       size_t leaf_idx,
                       const uint8_t (*proof)[32],
                       size_t proof_len,
                       size_t peak_idx,
                       size_t leaf_count,
                       const uint8_t expected_root[32]) {
    if (!hash_pair || !leaf || (!proof && proof_len != 0) ||
        !expected_root) return false;
    if (leaf_idx >= leaf_count) return false;

    /* Single bit-walk over leaf_count: count peaks, locate peak_idx's
     * height, and bracket the leaf range covered by that peak. Replaces
     * the prior peaks_h[64] + path_dirs[64] + peaks[64][32] = ~2.4 KB
     * stack footprint with a few scalars. Same bytes computed, fewer
     * intermediates materialized — important for constrained verifiers
     * (e.g. on-chain programs with sub-4 KB stack budgets). */
    size_t pcount = 0;
    int peak_height_signed = -1;
    uint64_t peak_lo = 0, peak_hi = 0;
    uint64_t cursor = 0;
    for (int b = 63; b >= 0; b--) {
        if ((((uint64_t)leaf_count >> b) & 1u) == 0u) continue;
        uint64_t span = (uint64_t)1 << b;
        if (pcount == peak_idx) {
            peak_height_signed = b;
            peak_lo = cursor;
            peak_hi = cursor + span;
        }
        cursor += span;
        pcount++;
    }
    if (peak_height_signed < 0) return false;       /* peak_idx >= pcount */
    if ((uint64_t)leaf_idx < peak_lo ||
        (uint64_t)leaf_idx >= peak_hi) return false; /* leaf not in claimed peak */
    uint8_t peak_height = (uint8_t)peak_height_signed;
    if (proof_len != (size_t)peak_height + (pcount - 1)) return false;
    uint64_t offset_in_peak = (uint64_t)leaf_idx - peak_lo;

    /* Climb the leaf's peak. Direction at height h is the parity of
     * (offset_in_peak >> h): 0 = we were a left child (sibling on right),
     * 1 = we were a right child (sibling on left). */
    uint8_t acc[32];
    memcpy(acc, leaf, 32);
    for (int h = 0; h < (int)peak_height; h++) {
        uint8_t tmp[32];
        if (((offset_in_peak >> h) & 1u) == 0u) {
            hash_pair(acc, proof[h], tmp);
        } else {
            hash_pair(proof[h], acc, tmp);
        }
        memcpy(acc, tmp, 32);
    }

    /* Right-fold the peak set without materializing it. The conceptual
     * left-to-right peak ordering puts the climbed acc at peak_idx and
     * the remaining peaks (in order, with peak_idx skipped) in the tail
     * of `proof`. So peak k is acc when k == peak_idx, else proof[off]
     * with off = peak_height + k - (k > peak_idx ? 1 : 0). */
    if (pcount == 1) {
        return memcmp(acc, expected_root, 32) == 0;
    }
    #define MERKLE__PEAK_AT(K) ((K) == peak_idx ? acc \
        : proof[(size_t)peak_height + (K) - ((K) > peak_idx ? 1u : 0u)])
    uint8_t fold[32];
    memcpy(fold, MERKLE__PEAK_AT(pcount - 1), 32);
    for (size_t i = pcount - 1; i > 0; i--) {
        uint8_t tmp[32];
        hash_pair(MERKLE__PEAK_AT(i - 1), fold, tmp);
        memcpy(fold, tmp, 32);
    }
    #undef MERKLE__PEAK_AT
    return memcmp(fold, expected_root, 32) == 0;
}

#endif /* MERKLE_IMPL */

#endif /* CENETEX_MERKLE_H */
