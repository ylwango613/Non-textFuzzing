Having now read the full file and traced all write paths, I can complete my analysis.

**Key findings from the audit:**

**`msrle_decode_pal4` (lines 33–126):**
- Line 43: loop condition `pixel_ptr <= avctx->width` (using `<=`) allows one iteration where `pixel_ptr == width`, but every actual array write at lines 83/89/109/111 is preceded by `if (pixel_ptr >= avctx->width) break;` — safe.
- Line 64: skip escape code 2 does `pixel_ptr += stream_byte` with no post-check, but subsequent writes are all guarded by the inner break condition.
- Line 99: run check uses `> avctx->width + 1` (allows one overshoot), but the inner loop guard `if (pixel_ptr >= avctx->width) break;` fires before any OOB write.
- `bytestream2_get_byteu(gb)` inside copy loop (line 82) is called AFTER the `pixel_ptr >= avctx->width` break — un-consumed bytes cause bytestream desync on early break, but NOT a memory safety issue.

**`msrle_decode_8_16_24_32` (lines 129–246):**
- Line 206: run-of-pixels `if (output + p1*(depth>>3) > output_end) continue;` — the `continue` skips consuming the color byte(s) from the stream, causing bytestream desync. Subsequent iterations re-apply the bounds check before every write, so no OOB write results.
- Line 176: copy path clips with `bytestream2_skip(gb, 2*(depth>>3))` instead of `p2*(depth>>3)` bytes, a wrong-skip count causing bytestream desync for large p2. Still no OOB write because output bounds are rechecked.
- `p1`/`p2` are always unsigned byte values (0–255); multiplied by at most 4 (for depth=32) gives max 1020 — no integer overflow risk.
- Line 167: `int pos` vs `unsigned int width` comparison — if `pos` overflows to negative, unsigned promotion makes it larger than any `width`, catching it. Safe.
- `output_end` is correctly recomputed per-line for both the end-of-line and skip cases.

Every array write in both decoders is guarded by a pre-write bounds check. No reachable OOB write path exists.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
