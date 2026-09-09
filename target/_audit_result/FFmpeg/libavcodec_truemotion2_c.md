I have now read the entire file and traced all relevant data flows. Here is my complete analysis:

**Group 1 (lines 1–221): Huffman tree / VLC building** — `huff.nodes` is bounded to ≤ 0x10000, `max_num` therefore ≤ 32769. Both allocations are guarded, recursion is bounded by `huff.max_bits ≤ 25`. `tm2_get_token` indexes `code->recode[val]` with `val` in `[0, code->length-1]`. Clean.

**Group 2 (lines 250–399): Stream reading** — `len` is guarded against overflow before `skip` is computed. `toks` is bounded to ≤ 0xFFFFFF before `av_reallocp_array`. Token bounds are validated in the fill loop. Clean.

**Group 3 (lines 400–763): Block decoders** — `last`/`clast` are within the `2*width`-int allocation. Motion vector is clipped and validated. Edge-extension `Y[-4]` and `Y[w+3]` land within the padded rows/cols. Clean.

**Group 4 (lines 948–992): `decode_init` — CRITICAL FINDING**

Lines 972–989:
```c
w += 8;  // int w = avctx->width + 8
h += 8;  // int h = avctx->height + 8
l->Y_base = av_calloc(w * h, 2 * sizeof(*l->Y_base));   // line 974
...
l->Y2 = l->Y1 + w * h;                                  // line 979
w = (w + 1) >> 1;
h = (h + 1) >> 1;
l->UV_base = av_calloc(w * h, 4 * sizeof(*l->UV_base)); // line 982
l->U2 = l->U1 + w * h;                                  // line 987
l->V1 = l->U2 + w * h;                                  // line 988
l->V2 = l->V1 + w * h;                                  // line 989
```

`w` and `h` are `int`. The expressions `w * h` are computed in **32-bit signed int arithmetic** before implicit conversion to `size_t` for `av_calloc`. For large, attacker-controlled `avctx->width` / `avctx->height`, the product wraps to a small positive value. `av_calloc`'s internal `size_mult` overflow check only sees the already-truncated operand, so it allocates a tiny buffer.

**Concrete exploit dimensions — width = height = 131072 (multiple of 4):**
- w = 131080 = 0x20008, h = 131080
- `w * h` as int32: 0x20008² mod 2³² = 0x00200040 = **2,097,216** → `av_calloc(2097216, 8)` = ~16 MB (succeeds)
- After halving: w = 65540 = 0x10004, h = 65540
- `w * h` as int32: 0x10004² mod 2³² = 0x00080010 = **524,304** → `av_calloc(524304, 16)` = ~8 MB (succeeds)
- Both allocations succeed, both massively under-sized.

During `tm2_decode_blocks` with bw = bh = 32768 blocks, by row 7 (by=7, bx=32767):
- Y index = Y_base + 131080×4 + 4 + 7×4×131080 + 32767×4 = Y_base + **4,325,632**
- Y_base total: 2 × 2,097,216 = **4,194,432** ints
- OOB write starts **131,200 ints (~512 KB) past** the allocation, progressively growing.

The written values are clipped pixel data (av_clip_uint8 outputs), which are partially attacker-controlled via crafted delta/Huffman tokens. Adjacent heap metadata (tcache bins, free-list pointers) can be overwritten, enabling heap exploitation → RCE.

No dimension upper-bound check exists in `decode_init` — only `(avctx->width & 3)` alignment is verified.

---

## VULN: Integer Overflow in decode_init Leading to Heap Under-Allocation and OOB Write
- **漏洞类别**: memory-safety
- **函数**: decode_init()
- **行号**: 972-989
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: `ffmpeg -i crafted.avi -f null -` → `avformat_open_input()` → AVI demuxer sets `avctx->width` / `avctx->height` from container header → `avcodec_open2()` → `decode_init()` → `l->Y_base = av_calloc(w * h, ...)` (integer overflow at line 974) → `tm2_decode_blocks()` → block decoder macros (e.g., `tm2_apply_deltas()`, `tm2_high_chroma()`) write OOB
- **描述**: In `decode_init()`, `w` and `h` are declared as `int` (lines 951-952: `int w = avctx->width, h = avctx->height`). After `w += 8; h += 8;` (lines 972-973), the expression `w * h` on lines 974, 979, 982, 987, 988, and 989 is evaluated in **signed 32-bit integer arithmetic** before implicit conversion to `size_t`. For attacker-controlled width = height = 131072 (a valid multiple-of-4 value that passes the only dimension check at line 953), `w = 131080`, `h = 131080`, and `w * h = 131080² mod 2³² = 2,097,216` — a small positive number. `av_calloc(2,097,216, 8)` succeeds and allocates only ~16 MB. The subsequent pointer arithmetic (`l->Y2 = l->Y1 + w * h`, line 979) also uses the overflowed result. When `tm2_decode_blocks()` later iterates over the full `bw × bh = 32768 × 32768` block grid using the real (`avctx->width`-derived) strides, array accesses begin exceeding the under-sized buffer at approximately block row 7, causing a heap overflow.
- **触发条件**: Craft an AVI (or other container supported by FFmpeg) wrapping a TrueMotion 2 video track with `width = height = 131072` (or any pair of multiples-of-4 whose padded values `w+8` satisfy `(w+8)*(h+8) mod 2³² < actual_frame_size`). The file must contain at least one valid TM2 frame to reach the block-decoding loop. No authentication, special privileges, or non-default build options are required.
- **安全影响**: The heap overflow writes partially attacker-controlled data (clipped pixel values from crafted Huffman/delta streams) into memory beyond `l->Y_base`. On a typical glibc heap, adjacent allocations or tcache/bin metadata are overwritten starting ~512 KB past the allocation. This provides a strong primitive for heap exploitation, with realistic potential for **Remote Code Execution** when the TM2 decoder is invoked via a media player, browser plug-in, or automated transcoding pipeline. Even without controlled exploitation, the overflow reliably crashes the process (**Denial of Service**).

<!-- AUDIT_PROMPT_VERSION: 1 -->
