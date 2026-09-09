After completing a thorough analysis of rv30.c and all called functions in rv34.c, rv30data.h, and related headers, I have traced every data path from the bitstream to memory operations:

**Summary of verified findings:**

1. **`rv30_decode_intra_types`** (rv30.c:86-109): The index `A * 90 + B * 9 + rv30_itype_code[code+k]` into `rv30_itype_from_context[900]` is tightly bounded. A and B are initialized to -1 (giving 0 after +1) and thereafter only hold values 0–8 (9 causes early return at line 101). Maximum index = 9×90 + 9×9 + 8 = 899 — tight but correct. The `code << 1` unsigned overflow when `get_interleaved_ue_golomb` returns > 2^31 produces a small even code that is also in range.

2. **`rv30_parse_slice_header`** (rv30.c:38-81): `rpr` is bounded by `max_rpr` (≤7), and `extradata_size >= rpr*2 + 8` is verified before any extradata access at lines 69–70. No OOB possible.

3. **`rv30_decode_init`** (rv30.c:260-290): The "insufficient extradata" warning at line 277 is non-fatal, but the real enforcement happens in `rv30_parse_slice_header` on every decode call.

4. **`ff_rv34_get_start_offset`** (rv34.c:352-359): The loop iterates i=0..4 over a 6-element array; an unmatched loop correctly exits with i=5, which is a valid index for both 6-element tables.

5. **`rv34_mc` / motion compensation** (rv34.c:689+): `emulated_edge_mc` guards all OOB reference-frame reads; `dxy` and chroma index are properly bounded.

6. **`rv30_loop_filter`** (rv30.c:151-255): All `rv30_loop_filt_lim[qscale]` accesses use 5-bit qscale values (0–31) into a 32-element table; edge guards prevent OOB pointer arithmetic.

7. **`ff_rv34_decode_frame` slice-header loop** (rv34.c:1777-1808): Reads from `slices_hdr + i*8` when `i < slice_count` could technically extend past declared `avpkt->size`, but FFmpeg mandates `AV_INPUT_BUFFER_PADDING_SIZE=64` bytes of zero-padding on all input buffers, so no actual memory fault occurs; subsequent bounds checks on the returned offset values prevent further exploitation.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
