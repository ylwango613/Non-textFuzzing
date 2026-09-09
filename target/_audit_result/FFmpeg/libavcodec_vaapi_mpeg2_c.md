Based on my thorough analysis of the file and full call-chain context, I have the following findings:

**`vaapi_mpeg2_start_frame` (lines 79-85):** The reference picture dereferences `s->next_pic.ptr->f` and `s->last_pic.ptr->f` without null checks, BUT `mpegvideo_dec.c:310-346` (`ff_mpv_alloc_dummy_frames`) allocates dummy frames for missing references before the hwaccel callback is ever invoked — mitigated.

**`vaapi_mpeg2_decode_slice` line 145:** `init_get_bits(&gb, buffer, 8 * size)` — return value unchecked. If `size ≥ 0x10000000 (268 MB)`, then `8 * size` wraps in uint32_t and converts to a negative `int`, causing `init_get_bits` to set `gb.buffer = NULL`. Subsequent `get_bits_long` would dereference NULL. However, MPEG-2 slice sizes are bounded by a single macroblock row (kilobytes) — this overflow is physically unreachable.

**`iq_matrix` loop (lines 98–104):** All indices are constant-bounded at [0, 63]; no overflow possible.

**`buf_end - buf_start` arithmetic in `mpeg_decode_slice:1426-1432`:** Minimum computable size passed to the hwaccel is 2 bytes (when `avpriv_find_start_code` returns immediately), and `init_get_bits` succeeds; the subsequent start-code check at line 146 returns `AVERROR_INVALIDDATA` — no memory safety impact.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
