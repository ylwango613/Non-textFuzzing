`dctref.c` is a 124-line pure-math reference DCT implementation. Analysis:

- All array accesses in `ff_ref_fdct` and `ff_ref_idct` operate on a fixed 8×8 (64-element) block using bounded loop indices (max computed index = 56+7 = 63). No out-of-bounds possible.
- The static `coefficients[64]` array is initialized in `ff_ref_dct_init` with indices capped at 63 (i∈{8,16,…,56}, j∈{0..7} → max i+j = 63). No overflow.
- No heap allocations (`av_malloc`/`malloc`) anywhere in this file.
- No external/untrusted input affects array sizing or loop bounds — the `block` pointer is a caller-supplied fixed 8×8 buffer.
- No integer arithmetic that could overflow to affect memory safety.
- The file is used only in the test harness (`tests/dct.c`), not in any media demuxer/decoder path that processes attacker-controlled files.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
