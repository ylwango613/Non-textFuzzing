I've now fully analyzed the file. Let me summarize my technical findings:

**`avs.c` — Complete Analysis**

The decoder is 191 lines with a fixed frame size (318×198 PAL8). I traced every data flow:

1. **Palette block (lines 76–93)**: `first`/`last` read from `AV_RL16(buf)` and `AV_RL16(buf+2)` occur *before* the bounds check at line 82. When `avpkt->size == 4` exactly, after `buf += 4` at line 74, `buf == buf_end`. However, this is not exploitable because AVPacket data is always padded with at least `AV_INPUT_BUFFER_PADDING_SIZE` (64) zero-initialized bytes beyond the declared size (confirmed in avcodec.h:2360). The reads return 0, and the subsequent check `buf_end - buf < 8` at line 82 correctly triggers `AVERROR_INVALIDDATA`.

2. **Vector table access (line 138)**: `vect = &buf[*table++ * (vect_w * vect_h)]`. `*table` is a `uint8_t` (0–255). Maximum index = `255 * (vect_w*vect_h)`. The vector buffer is exactly `256 * vect_w * vect_h` bytes, so vect access `vect[2*vect_w+j]` hits at most byte `255*vect_w*vect_h + 2*vect_w + (vect_w-1) = 256*vect_w*vect_h - 1` — exactly the last byte. No overflow.

3. **Output pixel writes (lines 139–145)**: Frame is fixed 318×198. y goes 0→198-vect_h in steps of vect_h, x goes 0→318-vect_w in steps of vect_w, j < vect_w. Maximum write: `out[197*stride + 317]` — within bounds.

4. **Integer arithmetic**: `256*vect_w*vect_h` ≤ 2304; `3*(last-first)` ≤ 768; `map_size` ≤ 1980. No overflow risks.

5. **`p->data[1]` palette write**: `pal[i]` with i ∈ [first, last), both bounded to [0, 256]. PAL8 palette is always 1024 bytes (256 × uint32_t). Safe.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
