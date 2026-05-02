/*
 * fuzz_decode_verify.c — libFuzzer harness for raw-bytes → decode → verify.
 *
 * fuzz_verify.c exercises merkle_mmr_verify with structured inputs. This
 * harness exercises the wire-level path that an on-chain verifier would
 * actually take: receive raw calldata bytes, parse them via
 * merkle_mmr_proof_decode, then call merkle_mmr_verify on the decoded
 * values. Adversarial inputs go straight into the decoder, so any OOB
 * read or UB in the parser is caught here.
 *
 * Input layout fed by libFuzzer:
 *   [ 0..31] expected_root
 *   [32..]   raw calldata bytes (passed unmodified to decode)
 *
 * Build (CI only — clang required):
 *   clang -std=c11 -O1 -g -fsanitize=fuzzer,address,undefined \
 *         -Iinclude -Itests tests/fuzz_decode_verify.c -o fuzz_decode_verify
 * Run:
 *   ./fuzz_decode_verify -max_total_time=60
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

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 32) return 0;
    uint8_t expected_root[32];
    memcpy(expected_root, data, 32);

    uint8_t leaf[32];
    uint64_t leaf_idx = 0, leaf_count = 0, peak_idx = 0;
    uint8_t proof[MERKLE_MMR_MAX_PROOF_LEN][32];
    size_t proof_len = 0;

    if (!merkle_mmr_proof_decode(data + 32, size - 32,
                                  leaf, &leaf_idx, &leaf_count,
                                  &peak_idx, proof, &proof_len)) {
        return 0;
    }

    /* Stay inside the spec-defined range so we don't waste budget on
     * undefined territory. The verifier itself is well-defined for any
     * size_t inputs, but SPEC §2 caps leaf_count at 2^63 - 1. */
    if (leaf_count >= ((uint64_t)1 << 63)) return 0;

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
