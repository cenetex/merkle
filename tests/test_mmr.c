/*
 * cenetex/merkle — test_mmr.c
 *
 * Builds the spec-canonical SHA-256 MMR over leaves
 *   leaf_i = SHA-256("leaf-" || ascii(i))    for i in 0..15
 * and pins the resulting root + proofs as golden vectors. Any future
 * port (Rust, Solidity, TypeScript, Solana program) is correct iff it
 * reproduces these exact bytes.
 *
 * Bring your own hash: the MMR primitive is hash-agnostic. The hash
 * function chosen here (SHA-256) is the one Signal uses for #285;
 * other consumers can build their own goldens with a different H.
 */

#define MERKLE_IMPL
#include "merkle.h"
#include "sha256.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures = 0;

#define ASSERT(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        failures++; \
    } \
} while (0)

#define ASSERT_HEX(actual, expected_hex) do { \
    char hex[65]; \
    for (int _i = 0; _i < 32; _i++) snprintf(hex + _i*2, 3, "%02x", (actual)[_i]); \
    hex[64] = '\0'; \
    if (strcmp(hex, (expected_hex)) != 0) { \
        fprintf(stderr, "  FAIL %s:%d: expected %s\n               got %s\n", \
                __FILE__, __LINE__, (expected_hex), hex); \
        failures++; \
    } \
} while (0)

/* SPEC §1: hash callback is `out = SHA-256(left || right)`. */
static void sha256_pair(const uint8_t left[32], const uint8_t right[32],
                         uint8_t out[32]) {
    uint8_t buf[64];
    memcpy(buf, left, 32);
    memcpy(buf + 32, right, 32);
    sha256_bytes(buf, 64, out);
}

static void make_leaf(int i, uint8_t out[32]) {
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "leaf-%d", i);
    sha256_bytes((const uint8_t *)buf, (size_t)n, out);
}

static void hex32(const uint8_t in[32], char out[65]) {
    for (int i = 0; i < 32; i++) snprintf(out + i*2, 3, "%02x", in[i]);
    out[64] = '\0';
}

/* Walk leaf counts 1..16, compute the root, print it. The first run
 * generates golden_vectors.txt; subsequent runs assert against pinned
 * values below. */
/* Pinned 2026-04-29 from a clean run of `GOLDEN_EMIT=1 ./test_mmr`.
 *
 * If you ever change this table, you have either:
 *   (a) found a real bug in the reference, in which case update the
 *       spec version and notify every verifier; or
 *   (b) introduced canonical-form drift, in which case roll back. */
static const char *golden_roots[16] = {
    /*  1 leaves */ "d2dbf006f96dd05044a8f63d8f118f23925ba4cc5750f8b6c8e287fd506c8188",
    /*  2 leaves */ "8b0f563106070048a1057926820c7118dec20b8a73715544f4528487c16dc0d7",
    /*  3 leaves */ "d67d9c98dea63cd27037f054b1991a8c5f1518df375b9c0bcdac15ba4ef853ed",
    /*  4 leaves */ "476c4a255bbaa3fa397182c77cb1bc85be71aa10349349f67e5c2bdd0453bfa0",
    /*  5 leaves */ "860a3896f4e89ce155ab1520180baa7eed0e61fd6ea331606090f564b5e8b30a",
    /*  6 leaves */ "1c94cf83da99191db4c73faec32c47adeb8e2722cb1ae5a1a5285a6e24797a7b",
    /*  7 leaves */ "cb198ed6975098c9c8e3180acecdfe4b05ecdf716c0bafcedc8b26f7306bb62e",
    /*  8 leaves */ "6e421edd382a1e4504a4857be5298412253e3d30f8a560b7c4c69029e58fdbec",
    /*  9 leaves */ "e4bfe3e02ddd11be7cb783bb0c67561d7daddb9b81b1f82a77255f2d9fc9acc3",
    /* 10 leaves */ "f90ef0b21eff4c0dd04ddf6b76d94e391412a4fa6b54ab35d475aa0e0dfa3b73",
    /* 11 leaves */ "db46d168f0ede8a331863372046124954e95b9308b2a4ffa2879b0aed5a1f7ec",
    /* 12 leaves */ "be64b6cd3671b56516241bb4e211e7b7db479b7f405a1a153f4a850039c4320a",
    /* 13 leaves */ "566576cb416a9ec24c5cb1c5ad9db82892330dbc93691778db84cef22cf92f41",
    /* 14 leaves */ "c7a6e3224a8387e230aa7c1345fb7f4409ec8aace8cc7dc5a96d161512f6a5c3",
    /* 15 leaves */ "289cbda171dfc86f634910faa35aed353d8bca43c4779df432a82bddc4c9ceac",
    /* 16 leaves */ "f55f58edc47c548d1b210a60ae084f3d34bae5df55e93f8bdc5725406e1b7dae",
};

static void test_root_at_each_count(void) {
    fprintf(stderr, "test_root_at_each_count:\n");
    /* On first run we emit the goldens. After they're pinned we
     * compare. Toggle by env var GOLDEN_EMIT=1. */
    int emit = getenv("GOLDEN_EMIT") != NULL;
    merkle_mmr_t *m = merkle_mmr_new(sha256_pair);
    ASSERT(m != NULL);
    for (int i = 0; i < 16; i++) {
        uint8_t leaf[32];
        make_leaf(i, leaf);
        merkle_mmr_append(m, leaf);
        uint8_t root[32];
        merkle_mmr_root(m, root);
        char hex[65];
        hex32(root, hex);
        if (emit) {
            fprintf(stderr, "    /* %2d leaves */ \"%s\",\n", i + 1, hex);
        } else {
            /* Skip leaf counts where the golden is "0" (placeholder);
             * those get filled in on the next run. */
            if (strcmp(golden_roots[i], "0") == 0) continue;
            if (strcmp(hex, golden_roots[i]) != 0) {
                fprintf(stderr, "    drift at leaf_count=%d\n", i + 1);
                fprintf(stderr, "      expected %s\n", golden_roots[i]);
                fprintf(stderr, "      got      %s\n", hex);
                failures++;
            }
        }
    }
    merkle_mmr_free(m);
}

static void test_proof_round_trip(void) {
    fprintf(stderr, "test_proof_round_trip:\n");
    /* Build a 13-leaf MMR (peaks at heights [3, 2, 0]) and verify a
     * proof for every leaf round-trips against the live root. */
    merkle_mmr_t *m = merkle_mmr_new(sha256_pair);
    uint8_t leaves[13][32];
    for (int i = 0; i < 13; i++) {
        make_leaf(i, leaves[i]);
        merkle_mmr_append(m, leaves[i]);
    }
    uint8_t root[32];
    merkle_mmr_root(m, root);
    for (int i = 0; i < 13; i++) {
        uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
        size_t peak_idx = 0;
        int len = merkle_mmr_proof(m, (size_t)i, proof, &peak_idx);
        ASSERT(len > 0);
        bool ok = merkle_mmr_verify(sha256_pair, leaves[i], (size_t)i,
                                     (const uint8_t (*)[32])proof,
                                     (size_t)len, peak_idx,
                                     13, root);
        if (!ok) {
            fprintf(stderr, "    proof verify FAILED for leaf %d\n", i);
            failures++;
        }
    }
    merkle_mmr_free(m);
}

static void test_proof_rejects_tamper(void) {
    fprintf(stderr, "test_proof_rejects_tamper:\n");
    merkle_mmr_t *m = merkle_mmr_new(sha256_pair);
    uint8_t leaves[7][32];
    for (int i = 0; i < 7; i++) {
        make_leaf(i, leaves[i]);
        merkle_mmr_append(m, leaves[i]);
    }
    uint8_t root[32];
    merkle_mmr_root(m, root);
    uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
    size_t peak_idx = 0;
    int len = merkle_mmr_proof(m, 3, proof, &peak_idx);
    ASSERT(len > 0);
    /* Flip a bit in the leaf — verify must reject. */
    uint8_t bad_leaf[32];
    memcpy(bad_leaf, leaves[3], 32);
    bad_leaf[0] ^= 0x01;
    bool ok = merkle_mmr_verify(sha256_pair, bad_leaf, 3,
                                 (const uint8_t (*)[32])proof,
                                 (size_t)len, peak_idx, 7, root);
    ASSERT(!ok);
    /* Flip a bit in the root — verify must reject. */
    uint8_t bad_root[32];
    memcpy(bad_root, root, 32);
    bad_root[31] ^= 0x80;
    ok = merkle_mmr_verify(sha256_pair, leaves[3], 3,
                            (const uint8_t (*)[32])proof,
                            (size_t)len, peak_idx, 7, bad_root);
    ASSERT(!ok);
    /* Flip a bit in a proof hash — verify must reject. */
    proof[0][0] ^= 0x01;
    ok = merkle_mmr_verify(sha256_pair, leaves[3], 3,
                            (const uint8_t (*)[32])proof,
                            (size_t)len, peak_idx, 7, root);
    ASSERT(!ok);
    merkle_mmr_free(m);
}

static void test_position_arithmetic(void) {
    fprintf(stderr, "test_position_arithmetic:\n");
    /* Pin the leaf-index-to-position mapping from SPEC §2. */
    static const struct { uint64_t leaf; size_t pos; } pinned[] = {
        {0, 1}, {1, 2}, {2, 4}, {3, 5},
        {4, 8}, {5, 9}, {6, 11}, {7, 12},
        {8, 16}, {9, 17}, {10, 19}, {11, 20},
    };
    for (size_t k = 0; k < sizeof(pinned)/sizeof(pinned[0]); k++) {
        size_t got = merkle_leaf_index_to_pos(pinned[k].leaf);
        if (got != pinned[k].pos) {
            fprintf(stderr, "    leaf %llu: expected pos %zu, got %zu\n",
                    (unsigned long long)pinned[k].leaf,
                    pinned[k].pos, got);
            failures++;
        }
    }
    /* And pin a few peak-height layouts. */
    uint8_t heights[64];
    size_t n = merkle_peak_heights(11, heights);
    ASSERT(n == 3 && heights[0] == 3 && heights[1] == 1 && heights[2] == 0);
    n = merkle_peak_heights(7, heights);
    ASSERT(n == 3 && heights[0] == 2 && heights[1] == 1 && heights[2] == 0);
    n = merkle_peak_heights(8, heights);
    ASSERT(n == 1 && heights[0] == 3);
    n = merkle_peak_heights(1, heights);
    ASSERT(n == 1 && heights[0] == 0);
}

/* For every count C in 1..MAX_N, build a fresh MMR and verify every
 * leaf's proof round-trips against the snapshot's root. Catches drift
 * between proof construction and verification, and would have caught
 * the torn-write regression class fixed in the previous PR by failing
 * round-trips at the irregular peak counts. */
static void test_property_round_trip_dense(void) {
    fprintf(stderr, "test_property_round_trip_dense:\n");
    enum { MAX_N = 128 };
    uint8_t leaves[MAX_N][32];
    for (int i = 0; i < MAX_N; i++) make_leaf(i, leaves[i]);
    for (size_t C = 1; C <= MAX_N; C++) {
        merkle_mmr_t *m = merkle_mmr_new(sha256_pair);
        for (size_t i = 0; i < C; i++) merkle_mmr_append(m, leaves[i]);
        uint8_t root[32];
        merkle_mmr_root(m, root);
        for (size_t i = 0; i < C; i++) {
            uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
            size_t peak_idx = 0;
            int len = merkle_mmr_proof(m, i, proof, &peak_idx);
            if (len < 0) {
                fprintf(stderr, "    proof build failed C=%zu leaf=%zu\n", C, i);
                failures++;
                continue;
            }
            bool ok = merkle_mmr_verify(sha256_pair, leaves[i], i,
                                         (const uint8_t (*)[32])proof,
                                         (size_t)len, peak_idx, C, root);
            if (!ok) {
                fprintf(stderr, "    verify failed C=%zu leaf=%zu\n", C, i);
                failures++;
            }
        }
        merkle_mmr_free(m);
    }
}

/* SPEC §5: an empty MMR's root is 32 zero bytes, and the verifier must
 * reject any proof against it (leaf_idx < leaf_count is unsatisfiable). */
static void test_empty_mmr(void) {
    fprintf(stderr, "test_empty_mmr:\n");
    merkle_mmr_t *m = merkle_mmr_new(sha256_pair);
    ASSERT(m != NULL);
    ASSERT(merkle_mmr_leaf_count(m) == 0);
    ASSERT(merkle_mmr_node_count(m) == 0);

    uint8_t root[32];
    /* Pre-fill with non-zero so we can detect that root() actually wrote. */
    memset(root, 0xab, 32);
    merkle_mmr_root(m, root);
    uint8_t zero[32] = {0};
    ASSERT(memcmp(root, zero, 32) == 0);

    /* Verifier must reject: leaf_idx (0) is not < leaf_count (0). */
    uint8_t leaf[32] = {0};
    bool ok = merkle_mmr_verify(sha256_pair, leaf, 0,
                                 NULL, 0, 0, 0, root);
    ASSERT(!ok);

    /* Proof construction on empty MMR must fail. */
    uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
    size_t peak_idx = 0;
    int len = merkle_mmr_proof(m, 0, proof, &peak_idx);
    ASSERT(len < 0);

    merkle_mmr_free(m);
}

int main(void) {
    test_position_arithmetic();
    test_root_at_each_count();
    test_proof_round_trip();
    test_proof_rejects_tamper();
    test_property_round_trip_dense();
    test_empty_mmr();
    if (failures > 0) {
        fprintf(stderr, "\n%d failure(s)\n", failures);
        return 1;
    }
    fprintf(stderr, "all green\n");
    return 0;
}
