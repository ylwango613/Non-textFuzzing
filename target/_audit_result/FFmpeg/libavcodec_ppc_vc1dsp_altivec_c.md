After reading the complete file and all related context (template file, header, callers), I've performed a thorough analysis:

**`vc1_inv_trans_8x8_altivec` (line 138):** Operates on a fixed `int16_t block[64]` (128 bytes). All 8 `vec_ld`/`vec_st` calls use static offsets 0, 16, 32, …, 112, exactly covering bytes 0–127. No OOB possible.

**`vc1_inv_trans_8x4_altivec` (line 233):** Reads from `int16_t *block` at fixed offsets 0–48 (covering 4 rows of 8×int16, i.e. 64 bytes = exactly the 8×4 block). Dest writes use `vec_ste` at fixed offsets 0 and 4 per row — element-safe, always writing exactly 8 pixels per row, 4 rows total.

**Chroma MC functions (via `h264chroma_template.c`):** Standard AltiVec chroma MC with `h`-height loop controlled by the decoder, 8-byte writes per row via `vec_st`. The alignment comment ("stride % 16 == 0") is an invariant enforced by the frame buffer allocator, not a safety issue.

No dynamic allocation, no attacker-controlled size driving buffer bounds, no variable-width access from external data — the entire file is pure fixed-geometry SIMD math on pre-validated codec block buffers.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
