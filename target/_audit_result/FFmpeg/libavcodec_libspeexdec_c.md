Analysis complete. Summary of all paths examined:

- **Line 61** `extradata[37]`: guarded by `extradata_size < 47` check at line 56 — safe.
- **Line 94** `160 << spx_mode`: spx_mode is only reached after `speex_lib_get_mode(spx_mode)` returns non-NULL (lines 89-92), which limits it to {0,1,2}; result is {160,320,640} — no shift UB.
- **Lines 154-155** `buf_size = s->pktsize`: only ever *reduces* buf_size (pktsize ≤ 62 = original buf_size condition), then passed to `speex_bits_read_from` — no over-read.
- **Lines 138-168** stereo decode: `ff_get_buffer` allocates `frame_size × nb_channels × sizeof(int16_t)` bytes; `speex_decode_int` writes `frame_size` int16 mono samples; `speex_decode_stereo_int(output, frame_size, ...)` does in-place mono→stereo expansion writing exactly `frame_size×2` int16 values — fits the allocation.
- **Lines 71-73** `header->mode / nb_channels / rate`: mode validated by `speex_lib_get_mode`; nb_channels clamped to 1-2 at lines 98-103; rate only sets `avctx->sample_rate` — no unsafe use.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
