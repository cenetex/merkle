/*
 * fuzz_verify.c — libFuzzer harness for merkle_mmr_verify.
 *
 * The verifier is the load-bearing surface for any consumer that
 * mirrors this library on-chain or in another language: it must never
 * crash, read out of bounds, or behave nondeterministically on
 * adversarial calldata. ASan/UBSan catch the memory bugs; this harness
 * additionally pins the function-of-inputs property by running verify
 * twice and trapping on disagreement.
 *
 * Build (CI only — clang required):
 *   clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined \
 *         -Iinclude -Itests tests/fuzz_verify.c -o fuzz_verify
 * Run:
 *   ./fuzz_verify -max_total_time=60
 */
#define MERKLE_IMPL
#include "merkle.h"
#include "sha256.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void sha256_pair(const uint8_t l[32], const uint8_t r[32], uint8_t o[32]) {
    uint8_t buf[64];
    memcpy(buf, l, 32);
    memcpy(buf + 32, r, 32);
    sha256_bytes(buf, 64, o);
}

/* Input layout fed by libFuzzer:
 *   [ 0..31]  leaf hash
 *   [32..63]  expected root
 *   [64..71]  leaf_idx     (u64 LE)
 *   [72..79]  leaf_count   (u64 LE)
 *   [80..87]  peak_idx     (u64 LE)
 *   [88...]   proof hashes (32 bytes each, truncated to MAX_PROOF_LEN)
 */
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    enum { HEADER = 32 + 32 + 8 + 8 + 8 };
    if (size < HEADER) return 0;

    uint8_t leaf[32], expected_root[32];
    memcpy(leaf, data, 32);
    memcpy(expected_root, data + 32, 32);

    uint64_t leaf_idx = 0, leaf_count = 0, peak_idx = 0;
    memcpy(&leaf_idx,   data + 64, 8);
    memcpy(&leaf_count, data + 72, 8);
    memcpy(&peak_idx,   data + 80, 8);

    /* Stay inside the spec-defined range (SPEC §2: leaf_count < 2^63).
     * The verifier doesn't internally call leaf_index_to_pos, so larger
     * values wouldn't actually overflow it — but exploring outside the
     * defined range just wastes the fuzzer's budget. */
    if (leaf_count >= ((uint64_t)1 << 63)) return 0;

    size_t proof_bytes = size - HEADER;
    size_t proof_len = proof_bytes / 32;
    if (proof_len > MERKLE_MMR_MAX_PROOF_LEN) proof_len = MERKLE_MMR_MAX_PROOF_LEN;

    uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
    if (proof_len > 0) memcpy(proof, data + HEADER, proof_len * 32);

    bool a = merkle_mmr_verify(sha256_pair, leaf, (size_t)leaf_idx,
                                (const uint8_t (*)[32])proof, proof_len,
                                (size_t)peak_idx, (size_t)leaf_count,
                                expected_root);
    bool b = merkle_mmr_verify(sha256_pair, leaf, (size_t)leaf_idx,
                                (const uint8_t (*)[32])proof, proof_len,
                                (size_t)peak_idx, (size_t)leaf_count,
                                expected_root);
    if (a != b) __builtin_trap();
    return 0;
}
