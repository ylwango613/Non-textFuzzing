Key finding: in the **checked (default)** bitstream reader, `SKIP_COUNTER` is:

```c
name ## _index = FFMIN(name ## _size_plus8, name ## _index + (num))
```

So `SKIP_COUNTER(re, gb, -1)` with `re_index = 0` produces `FFMIN(size_plus8, UINT_MAX) = size_plus8` — clamped, not underflowed. The next `get_bits_left(gb) < 0` check in `do_decode` (line 276) catches the overrun and returns `AVERROR_INVALIDDATA`. No OOB read.

This protection is absent only under `UNCHECKED_BITSTREAM_READER`, a non-default compile-time flag, which the audit scope explicitly excludes.

All other candidate paths have been fully traced:

- `max_framesize = (frame_samples * 16 + 1024) * nb_channels` — all `int` operands bounded (uint16 × 2), no overflow, safe `size_t` assignment.
- `decode_buffer[ch]` allocated as `frame_samples + OFFSET` elements; the decode loop writes only `n < nb_samples ≤ frame_samples`, negative-index history slots (`dst[A..E]`) all land in the `[0..OFFSET-1]` prefix — in bounds.
- `memcpy` into `s->bitstream` bounded by `FFMIN(pkt->size - pkt_offset, max_framesize - bitstream_size)` with allocation `max_framesize + AV_INPUT_BUFFER_PADDING_SIZE` — in bounds.
- `update_residue_parameter` returning −1 (when `sum/count ≈ 1.0` → `av_ceil_log2(1) = −1`) propagates into `get_urice(gb, −1)` → `get_bits_long(gb, −1)`, which in the checked reader clamps the index and is caught by the overread guard.
- `s->nb_samples` (uint64_t, unbounded from extradata) is consumed only through `FFMIN` with `s->frame_samples` (≤ 65535) — no allocation or index scaled by it.
- `cb->count` overflow (~4B iterations) causes FP edge case only, no memory write.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
