**Pass 1 findings (cbs_apv.c lines 1-471):** PBU splitting loop validates `pbu_size` against remaining `size` before using it. Fragment assembly has no overflow path via attacker-controlled data. Tile arrays are fixed-size at `APV_MAX_TILE_COUNT = 400`.

**Pass 2 findings (cbs_apv_syntax_template.c):**

- `metadata_itu_t_t35` (line 308): `size_t read_size = payload_size - 1` underflows to `SIZE_MAX` when `payload_size == 0`, but `av_buffer_alloc(SIZE_MAX)` returns NULL → `AVERROR(ENOMEM)`. When `payload_size == 1` and `country_code == 0xff`, `--read_size` underflows to `SIZE_MAX` → same ENOMEM result. No heap write occurs.

- `metadata_user_defined` (line 406): `current->data_size = payload_size - 16` underflows when `payload_size < 16` → huge `data_size` → allocation failure → ENOMEM. Not exploitable for heap overflow.

- `metadata_bytes_left` (line 527): When `metadata_size` is small and stream has many 0xff bytes, `--metadata_bytes_left` underflows to `UINT32_MAX`. This corrupts accounting and the payload_size range check `pl->payload_size > metadata_bytes_left` becomes ineffective (always passes). However, subsequent `av_buffer_alloc` calls for large payload sizes fail with ENOMEM, and all reads are bounded by the `GetBitContext` (which covers only the PBU unit data). No heap write past allocated boundaries.

- `cbs_apv_derive_tile_info` (line 46): Division by zero when `frame_width == 0` gives `frame_width_in_mbs == 0` → `min_tile_width == 0` → `tile_width_in_mbs` can be 0 → SIGFPE. This is DoS, not memory safety.

- `tile` parsing (line 241-244): `8LL * comp_size` check protects against `skip_bits_long` integer overflow before it can be triggered.

- `av_assert0` in `cbs_apv_derive_tile_info` is always-enabled (confirmed in `avassert.h`), so the `num_tiles <= APV_MAX_TILE_COUNT` guard holds in all builds.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
