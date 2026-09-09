Key findings from batch analysis:

**speedhq.c** — 99 lines, purely static VLC table data (`ff_speedhq_vlc_table`, `ff_speedhq_level`, `ff_speedhq_run`). No runtime code, no memory operations.

**speedhqdec.c — batch 1 (lines 1–598)** — examined all critical paths:

- `decode_dct_block` (L141): `i` is checked against `MAX_INDEX=63` before `block[scantable[i]]`; `scantable` is a permutation of 0..63, `block[64]` is always in-bounds; `quant_matrix[i]` for i∈[0,63] is safe.
- `decode_alpha_block` (L101): `block[128]` stack array; `i >= 128` check fires before `block[i++] = level`, so writes only to indices 0..127.
- `decode_speedhq_field` slice-offset chain (L287–298): `slice_offsets[0]=start=4`, loop runs 3 times adding at most `AV_RL24()`'s max 16777215 each time → max accumulated offset ≈ 50MB — far below INT_MAX — no integer overflow possible. `AV_RL24` reads are proven in-bounds by `end >= start+3` invariant. `end - 3` subtraction cannot underflow because `end >= start+3 >= 7`.
- `second_field_offset` (L450–453): `AV_RL24(buf+1)` safe since `buf_size>=4`; bounds check `>= buf_size-3` correctly guards.
- Frame buffer writes in `decode_speedhq_border` and main loop: `avctx->coded_width/height = FFALIGN(width/height, 16)` provides the necessary padding for all DCT block writes at border positions.
- `linesize_a` / `dest_a` uninitialized only when `alpha_type == SHQ_NO_ALPHA`, and only consumed under `alpha_type != SHQ_NO_ALPHA` — logically consistent, not a bug.

**speedhqdec.c — batch 2 (lines 596–675)**: `speedhq_decode_init` — codec tag switch is exhaustive with a default error return; no memory allocations beyond `ff_idctdsp_init` / `ff_blockdsp_init` (internal, trusted).

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
