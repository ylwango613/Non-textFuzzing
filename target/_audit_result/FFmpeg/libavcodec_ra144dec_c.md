I've now read all relevant code paths:
- `ra144dec.c` (139 lines, complete)
- `ra144.h` (struct layout, constants)
- `ra144.c` key functions: `ff_subblock_synthesis`, `ff_copy_and_dup`, `add_wav`, `ff_interp`, `ff_rms`, table sizes for `ff_lpc_refl_cb`, `ff_gain_val_tab`, `ff_gain_exp_tab`, `ff_cb1_base`, `ff_cb2_base`, `ff_cb1_vects`, `ff_cb2_vects`

**Analysis summary:**

1. **Bit-indexed tables** — `lpc_refl[i] = ff_lpc_refl_cb[i][get_bits(&gb, sizes[i])]`: sizes `{6,5,5,4,4,3,3,3,3,2}` match table sizes `{64,32,32,16,16,8,8,8,8,4}` exactly. No OOB.

2. **Energy table** — `ff_energy_tab[get_bits(&gb, 5)]`: 5-bit index → 0..31, table has 32 entries. Safe.

3. **cb1/cb2 index** — 7-bit reads (0..127), tables `ff_cb1_vects[128][40]`, `ff_cb2_vects[128][40]`, `ff_cb1_base[128]`, `ff_cb2_base[128]` all have exactly 128 entries. Safe.

4. **gain index** — 8-bit read (0..255), `ff_gain_val_tab[256][3]` and `ff_gain_exp_tab[256]` fit exactly. Safe.

5. **`ff_copy_and_dup` offset** — `cba_idx` is 7-bit, non-zero path adds 19 → range 20..146. `adapt_cb[148]` (146+2). Source pointer `adapt_cb + (146-offset)` ranges from 0..126. Copy of `min(BLOCKSIZE=40, offset)` elements never exceeds array bounds. Safe.

6. **`curr_sblock[j+10]`** — j ∈ [0,39], index ∈ [10,49], array size 50. Safe.

7. **Total bit consumption** — 38 (LPC) + 5 (energy) + 4×29 (subblocks) = 159 bits ≤ 160 bits (20 bytes). The `buf_size < FRAME_SIZE` guard at line 80 ensures the buffer is large enough before `init_get_bits8`.

8. **Heap allocation** — `ff_get_buffer` called with `frame->nb_samples = NBLOCKS * BLOCKSIZE = 4*40 = 160` fixed samples; no user-controlled size multiplied before allocation.

No exploitable memory safety vulnerabilities are present in this decoder. It is a small, tightly bounded codec operating entirely on fixed-size data structures with bit-reads that are exactly matched to table dimensions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
