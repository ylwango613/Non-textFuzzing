The CBS framework's `cbs_read_unsigned` (cbs.c:599) calls `get_bits_left(gbc) < width` before every bit read, providing a universal bounds guard on the bitstream layer.

**Analysis summary across all groups:**

**Group 1 – `tile_header()` `tile_size_remaining` underflow (lines 210–213):** `tile_size` minimum is 10; `expected_tile_header_size` can be up to 25 (4-comp). Subtraction can wrap to ~UINT32_MAX. This allows `tile_data_size[c]` to be up to ~4 GB. However, `tile()` (line 241) guards with `get_bits_left(rw) < 8LL * comp_size` (64-bit arithmetic) before any skip, so no OOB read occurs. The underflow propagates as logic noise but not memory corruption.

**Group 2 – `metadata_bytes_left` underflow (lines 524–541):** If `metadata_size=0` and the PBU contains `0xff` type-extension bytes, `--metadata_bytes_left` wraps to UINT32_MAX, making subsequent `payload_size > metadata_bytes_left` checks trivially false. This allows processing payloads beyond the declared `metadata_size`, but the outer loop is bounded by `CBS_APV_MAX_METADATA_PAYLOADS=8` and the `GetBitContext` is bounded by the PBU size. No memory corruption.

**Group 3 – `metadata_itu_t_t35()` size_t underflow (lines 307–321):** `read_size = payload_size - 1` wraps if `payload_size=0`. Similarly `--read_size` wraps if country_code==0xff and payload_size==1. In both cases `av_buffer_alloc(SIZE_MAX)` returns NULL and the function returns AVERROR(ENOMEM). No heap corruption.

**Group 4 – `metadata_user_defined()` underflow (line 406):** `payload_size - 16` wraps for `payload_size < 16`. Same mitigation: `av_buffer_alloc(SIZE_MAX - k)` fails safely.

**Group 5 – `cbs_apv_derive_tile_info()` division by zero (cbs_apv.c:46–47):** With `frame_width=0`, `tile_width_in_mbs` can be 0, causing SIGFPE. This is a DoS (out of scope for memory-safety audit).

**Group 6 – Fixed-size arrays:** `tile[]`, `tile_size[]`, `payloads[]`, `frame_info[]` all bounded by compile-time constants with corresponding `num_tiles`/`num_frames`/loop-count constraints that are verified to stay in bounds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
