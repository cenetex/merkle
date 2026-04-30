/*
 * append_prove.c — minimal end-to-end usage example.
 *
 * Build:
 *   cc -std=c11 -O2 -Iinclude -Itests examples/append_prove.c -o append_prove
 * Run:
 *   ./append_prove
 *
 * Appends ten leaves, builds a proof for leaf 7, and verifies it
 * against the live root.
 */

#define MERKLE_IMPL
#include "../include/merkle.h"
#include "../tests/sha256.h"

#include <stdio.h>
#include <string.h>

static void sha256_pair(const uint8_t l[32], const uint8_t r[32], uint8_t o[32]) {
    uint8_t buf[64];
    memcpy(buf, l, 32); memcpy(buf + 32, r, 32);
    sha256_bytes(buf, 64, o);
}

static void make_leaf(int i, uint8_t out[32]) {
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "leaf-%d", i);
    sha256_bytes((const uint8_t *)buf, (size_t)n, out);
}

int main(void) {
    merkle_mmr_t *m = merkle_mmr_new(sha256_pair);

    uint8_t leaves[10][32];
    for (int i = 0; i < 10; i++) {
        make_leaf(i, leaves[i]);
        merkle_mmr_append(m, leaves[i]);
    }

    uint8_t root[32];
    merkle_mmr_root(m, root);
    printf("root: ");
    for (int i = 0; i < 32; i++) printf("%02x", root[i]);
    printf("\nleaf_count: %zu\n", merkle_mmr_leaf_count(m));
    printf("node_count: %zu\n", merkle_mmr_node_count(m));

    uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
    size_t peak_idx = 0;
    int len = merkle_mmr_proof(m, 7, proof, &peak_idx);
    printf("proof for leaf 7: %d hashes, peak_idx=%zu\n", len, peak_idx);

    bool ok = merkle_mmr_verify(sha256_pair, leaves[7], 7,
                                 (const uint8_t (*)[32])proof, (size_t)len,
                                 peak_idx, 10, root);
    printf("verify: %s\n", ok ? "OK" : "FAIL");

    merkle_mmr_free(m);
    return ok ? 0 : 1;
}
