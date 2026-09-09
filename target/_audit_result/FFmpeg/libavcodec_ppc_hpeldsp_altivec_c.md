I've completed a full analysis of `hpeldsp_altivec.c` (387 lines) including all related macros in `util_altivec.h` and the interface contract in `hpeldsp.h`. Key observations:

- **No memory allocation**: All functions operate on caller-provided buffers.
- **No external data parsing**: No fields from bitstreams or containers are read here.
- **AltiVec partial-store technique**: `avg_pixels8_altivec` loads/stores 16-byte vectors for 8-byte blocks — a standard AltiVec idiom (reads adjacent 8 bytes to preserve them in the aligned store). Frame buffers carry `AV_INPUT_BUFFER_PADDING_SIZE` (64 bytes) of padding that covers these over-reads.
- **Loop unrolling by 4** in `ff_put_pixels16_altivec`: The interface contract in `hpeldsp.h` guarantees h is a positive multiple of 4 for 16-wide blocks. No standalone bug.
- **`VEC_LD(1, pixels)`** in all bilinear functions reads 16 bytes starting at `pixels+1` (reads up to 17 bytes per row from the source) — again covered by the 64-byte padding in allocated frame planes.

No function in this file parses attacker-controlled sizes, allocates memory, performs pointer arithmetic from untrusted fields, or has any path reachable from crafted media input that bypasses callers' precondition checks.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
