After reading all 2029 lines of `flvdec.c` in four passes and chasing the relevant helper functions, here is a record of each group's analysis before the final determination.

**Pass 1 (lines 1–500):** `probe()` — the `d[5] == 0` guard forces `offset` to `0x00XXXXXX` (≤16 MB), so `offset + 100` cannot wrap in practice. `flv_set_video_codec()` reads exactly 1 byte for VP6/VP6A and returns 1 — all callers account for this. No issue.

**Pass 2 (lines 500–999):** `amf_get_string()` — length is 16-bit; `if (length >= buffsize)` guards every call site (`buffer[32]`, `str_val[1024]`, `buf[20]`). `parse_keyframes_index()` — `arraylen >> 28` limits `arraylen` to < 268 M; `8 × 268 435 455 = 2 147 483 640` fits in 32-bit `size_t`; no integer overflow. The loop bound is also protected by `avio_tell < max_pos − 1`. No issue.

**Pass 3 (lines 999–1520):** `flv_queue_extradata()` — `!size` guards zero; non-negative `size` is guaranteed by all callers (the `size < 0 || track_size < 0` check at line 1781 fires before any call site). The realloc-failure path for `mt_extradata_sz` leaves `mt_extradata_cnt` unchanged; cleanup in `flv_read_close()` iterates only up to the old count, never touching uninitialised entries. `flv_parse_mod_ex_data()` — `ex_size ≥ *size` check prevents over-read; `ex_size` is bounded at 65 536; the ex_type byte is consumed only when `*size > ex_size`, leaving `*size ≥ 0`. No memory-safety issue.

**Pass 4 (lines 1520–2029):** `flv_read_packet()` for-loop — `track_size` is set either from `size` (caught by `if (size < 0)` at top of loop) or from a fresh `avio_rb24` (24-bit, always non-negative). The checks at lines 1781 (`size < 0 || track_size < 0`), 1797 (`size < 3 || track_size < 3`), and 1844 (`size <= 0 || track_size < 0`) collectively ensure `track_size > 0` at every call to `av_get_packet()` and `flv_get_extradata()`. The Omnia A/XE workaround sets `extradata_size = 2` but the buffer always has at least 64 bytes of padding allocated. The `AudioChannelOrderCustom` channel-map loop reads stream bytes without crashing memory; the `next_track:` handler catches `track_size < 0` and re-syncs. `resync_buffer` accesses are bounded: `j ≤ RESYNC_BUFFER_SIZE−1`, `j1 ≤ 2×RESYNC_BUFFER_SIZE−1`, and the `lsize` guards ensure non-negative offsets into the array.

No externally triggerable memory-safety vulnerability (heap overflow, use-after-free, stack overflow, integer-overflow-to-underalloc, or OOB write/read) was found in any code path reachable by supplying a crafted FLV/KUX file.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
