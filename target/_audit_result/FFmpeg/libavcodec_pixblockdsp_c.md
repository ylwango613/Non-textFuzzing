The analysis is complete. `pixblockdsp.c` is 117 lines with four static functions and one init function. Every function operates on a **fixed** 8×8 block:

- `get_pixels_8_c` / `get_pixels_16_c` / `get_pixels_unaligned_16_c`: always iterate exactly 8 rows × 8 columns, with no dynamic size parameter.
- `diff_pixels_c`: same fixed 8×8 pattern.
- `ff_pixblockdsp_init`: only selects function pointers based on `bits_per_raw_sample`, no allocation.

There is no `malloc`/`realloc`, no externally-supplied size controlling a buffer access, no integer arithmetic feeding an allocation, and no direct file-derived fields. `stride`/`linesize` is an AVFrame property managed by the codec framework and its value does not control the number of elements read per row (always exactly 8). The `block` destination buffer in all callers (e.g., `ctx->blocks[N]` in `dnxhdenc.c`, `asvenc.c`) is a statically-declared `int16_t[64]` (128 bytes), exactly matching what each function writes. `AV_COPY128` copies a fixed 16 bytes (two `AV_COPY64` calls on 8-byte aliases) — no size variable involved.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
