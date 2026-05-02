/*
 * gen_vectors.c — emit portable conformance vectors.
 *
 * Walks leaf counts 1..16 with the canonical sha256("leaf-"+ascii(i))
 * derivation and dumps, for every (leaf_count, leaf_idx) tuple, the
 * snapshot root and the SPEC §4 calldata bytes for that leaf's proof.
 * Intended to be regenerated and committed to tests/vectors.txt; CI
 * regenerates and diffs, so any drift in root/proof/encode behavior
 * breaks the build.
 *
 * Build:
 *   cc -std=c11 -O2 -Iinclude -Itests tests/gen_vectors.c -o gen_vectors
 * Regenerate:
 *   ./gen_vectors > tests/vectors.txt
 *
 * Format (line-oriented, # comments allowed, blank lines ignored):
 *   leaf_count=<dec> leaf_idx=<dec> root=<hex64> encoded=<hex>
 *
 * `encoded` is exactly the byte sequence merkle_mmr_proof_encode emits
 * for that proof, so a verifier in any language can: hex-decode it,
 * call its own merkle_mmr_proof_decode equivalent, then verify against
 * the printed root. Pass = byte-for-byte canonical-form compatibility.
 */
#define MERKLE_IMPL
#include "merkle.h"
#include "sha256.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static void sha256_pair(const uint8_t l[32], const uint8_t r[32], uint8_t o[32]) {
    uint8_t buf[64];
    memcpy(buf, l, 32);
    memcpy(buf + 32, r, 32);
    sha256_bytes(buf, 64, o);
}

static void make_leaf(int i, uint8_t out[32]) {
    char buf[16];
    int n = snprintf(buf, sizeof(buf), "leaf-%d", i);
    sha256_bytes((const uint8_t *)buf, (size_t)n, out);
}

static void put_hex(const uint8_t *bytes, size_t len) {
    for (size_t i = 0; i < len; i++) printf("%02x", bytes[i]);
}

int main(void) {
    printf("# cenetex/merkle conformance vectors\n");
    printf("# spec_version=1 hash=sha256\n");
    printf("# leaf_i = sha256(\"leaf-\" || ascii_decimal(i))\n");
    printf("# fields per line: leaf_count=<dec> leaf_idx=<dec> root=<hex64> encoded=<hex>\n");
    printf("# encoded layout: SPEC.md section 4 calldata format\n");
    printf("#   leaf[32] | leaf_idx u64 LE | leaf_count u64 LE | peak_idx u64 LE | proof_len u64 LE | proof_hashes\n");
    printf("\n");

    enum { MAX_N = 16 };
    uint8_t leaves[MAX_N][32];
    for (int i = 0; i < MAX_N; i++) make_leaf(i, leaves[i]);

    for (int N = 1; N <= MAX_N; N++) {
        merkle_mmr_t *m = merkle_mmr_new(sha256_pair);
        for (int i = 0; i < N; i++) merkle_mmr_append(m, leaves[i]);
        uint8_t root[32];
        merkle_mmr_root(m, root);
        for (int i = 0; i < N; i++) {
            uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
            size_t peak_idx = 0;
            int len = merkle_mmr_proof(m, (size_t)i, proof, &peak_idx);
            uint8_t encoded[MERKLE_MMR_MAX_ENCODED_LEN];
            size_t enc_len = merkle_mmr_proof_encode(
                leaves[i], (uint64_t)i, (uint64_t)N, (uint64_t)peak_idx,
                (const uint8_t (*)[32])proof, (size_t)len,
                encoded, sizeof(encoded));
            printf("leaf_count=%d leaf_idx=%d root=", N, i);
            put_hex(root, 32);
            printf(" encoded=");
            put_hex(encoded, enc_len);
            printf("\n");
        }
        merkle_mmr_free(m);
    }
    return 0;
}
