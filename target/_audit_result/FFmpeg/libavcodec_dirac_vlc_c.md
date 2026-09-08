Having read all 1134 lines of `dirac_vlc.c` (in two batches), the header, and the sole caller in `diracdec.c`, I now compile my full analysis before rendering a verdict.

**Group 1 — LUT initialisation and index safety (lines 1098/1118)**

`LUTState lut = dirac_golomb_lut[*buf++]` uses a raw byte (0–255) as index into a 1024-entry LUT whose first 256 slots handle `STATE_START=0`. Every subsequent LUT access is `lut.state + *buf++` where `lut.state ∈ {0, 256, 512, 768}` and `*buf` is 0–255 → max index = 1023 < 1024. All LUT accesses are strictly in bounds.

**Group 2 — Speculative 8-ahead writes in `PROCESS_VALS` (lines 1079–1084)**

The macro always stores `dst[0]..dst[7]` unconditionally before the bounds check `if (dst >= last)`. On the surface this looks like a write past the end when fewer than 8 slots remain, but the caller `diracdec.c:956-957` explicitly pads the buffer:

```c
coef_buf_size = subband_coeffs(s, s->num_x - 1, s->num_y - 1, 0, tmp) + 8;   // +8 slots
coef_buf_size = (coef_buf_size << (1 + s->pshift)) + 512;
```

Mathematically, `subband_coeffs(num_x-1, num_y-1, ...)` yields the ceiling-maximum coefficient count across all slice positions (`ceil(w/num_x)·ceil(h/num_y)` summed over levels), so the entire speculative write range `dst[0..7]` always lands within the allocated padding area. No OOB write occurs.

**Group 3 — Flush PROCESS\_VALS over-reads input by 1 byte (lines 1106/1126)**

After the loop consumes `bytes-1` extra bytes plus the initial byte = `bytes` total, the mandatory flush `PROCESS_VALS` executes one final `lut = dirac_golomb_lut[lut.state + *buf++]` that reads `addr[bytes]` — one byte past the declared input length. However:

1. The read byte is only used to set `lut` for the next iteration, which never executes.
2. The post-flush write (`*dst++ = ...`) uses `val` computed from the previous, valid state — the OOB byte influences only `lut.state`, which determines whether a final spurious coefficient is emitted (a correctness issue, not a safety issue), and the write target `dst` is always within the allocated coefficient buffer (`dst < last`).
3. FFmpeg guarantees `AV_INPUT_BUFFER_PADDING_SIZE` (64) bytes of zero-padding after every input packet, so `addr[bytes]` is within allocated memory.

This is a latent read-1-byte-past-end, but it does not produce any out-of-bounds write, crash-reachable invalid read, or exploitable memory corruption.

**Group 4 — `coeffs = 0` or `bytes = 0` edge cases**

With `coeffs = 0`: `last = dst`, first `PROCESS_VALS` checks `dst >= dst` → true → returns before any damage. With `bytes = 0`: reads `addr[0]` and (in flush) `addr[1]`; `addr` is within the bitstream buffer's valid+padding zone, and the output writes land in the 8-element padding area. No actionable safety issue.

**Group 5 — Integer/sign considerations**

`val` is `uint16_t`/`uint32_t`; shift amounts in the LUT (`val0_bits`) are at most 5. `lut.num` is `int8_t` but the LUT only contains values 0–8. No overflow in array subscript arithmetic.

---

After exhaustive multi-pass review of every access pattern, buffer boundary, and integer arithmetic path in `dirac_vlc.c` and its call chain, no exploitable memory-safety vulnerability is present.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
