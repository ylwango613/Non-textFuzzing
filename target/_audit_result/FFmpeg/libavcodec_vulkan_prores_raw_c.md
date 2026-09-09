After thorough analysis of `vulkan_prores_raw.c` (431 lines), including all referenced headers, `prores_raw.h`, `prores_raw.c`, `vulkan_decode.c`, and `refstruct.c`, here are the key findings from each code group:

**Group 1 (lines 65–97, `vk_prores_raw_start_frame`):** Buffer allocation `prr->nb_tiles*sizeof(TileData)` — `nb_tiles` is `int`, bounded by `nb_tw * nb_th` where both come from 16-bit width/height (max ~4097×4097≈16.8M). `sizeof(TileData)=20`. Product is at most 336MB — no integer overflow. `ff_vk_get_pooled_buffer` confirmed to guarantee returned buffer ≥ requested size (reallocs on undersize).

**Group 2 (lines 99–130, `vk_prores_raw_decode_slice`):** Writes to `td[pp->nb_tiles]` without an explicit bounds check. `pp->nb_tiles` (uint32_t) is zero-initialized (confirmed: `av_refstruct_alloc_ext_c` zeros memory when `AV_REFSTRUCT_FLAG_NO_ZEROING` is absent). The outer loop in `prores_raw.c` calls `decode_slice` exactly `s->nb_tiles` times — `pp->nb_tiles` progresses 0→N−1, all in-bounds. `ff_vk_decode_add_slice` increments `*nb_slices` only on success (line 322). No exploitable OOB path found.

**Group 3 (lines 132–279, `vk_prores_raw_end_frame`):** `memcpy(pd_decode.qmat, prr->qmat, 64)` — both 64 bytes. `memcpy(pd_decode.lin_curve, prr->lin_curve, sizeof(pd_decode.lin_curve))` — both 16 bytes. No overflow.

**Group 4 (lines 281–359, `add_desc`, `init_decode_shader`, `init_idct_shader`):** `SPEC_LIST_CREATE(sl, 2+64, (2+64)*sizeof(uint32_t))` allocates 69×4=276-byte data array and 69 entry slots. 66 `SPEC_LIST_ADD` calls consume 264 bytes/66 slots — within capacity. No OOB.

**Ignored return value:** `ff_vk_host_map_buffer()` in `start_frame` — error ignored. In `decode_slice`, `vp->slices_buf` is checked for NULL before use; failure falls through to the else branch safely. Not a memory safety bug.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
