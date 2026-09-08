Complete analysis of `binkdsp.c`:

**Summary of what was read and checked:**

- **File** (159 lines, read in full): Pure DSP helper — IDCT column/row transforms, scale_block, add_pixels8, and init.
- **binkdsp.h**: Defines `BinkDSPContext` with four function pointers; no dynamic sizing.
- **bink.c caller sites**: `stride = frame->linesize[plane_idx]` (from frame allocator, not raw bitstream); block/dctblock are stack arrays declared locally.

**Per-function analysis:**

| Function | Array accesses | Allocation | External input |
|---|---|---|---|
| `bink_idct_col` | Fixed indices: 0,8,16,24,32,40,48,56 | none | none |
| `bink_idct_c` | `temp[64]` stack, fixed offsets | stack only | none |
| `bink_idct_add_c` | Loops i,j ∈ [0,7] on fixed 8×8 | none | linesize from frame (not bitstream) |
| `bink_idct_put_c` | `temp[64]` stack, fixed offsets | stack only | none |
| `scale_block_c` | dst1/dst2 indexed 0..7 as uint16_t* | none | linesize from frame |
| `add_pixels8_c` | pixels[0..7], block[0..7] fixed | none | none |

No `av_malloc`/`memcpy`/`memmove` with variable length. No bitstream/container field parsing. All array indices are compile-time constants or loop bounds `[0,7]`. The file contains no code path that reads from untrusted external input directly.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
