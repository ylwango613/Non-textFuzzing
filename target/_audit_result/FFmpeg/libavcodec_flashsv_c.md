After reading the full file and doing targeted analysis, let me trace the critical arithmetic and bounds carefully.

**Analysis of key security-sensitive regions:**

**1. `decode_hybrid` line 85-89 — `AV_RB16` with single-byte guard:**
- Check at line 85 ensures only 1 byte available, but `AV_RB16(sptr)` reads 2 bytes
- `sptr_end = zstream->next_out` = end of inflated data in `tmpblock`
- `tmpblock` size = `3 * block_size` (block_width × block_height × 3)
- Maximum inflated data for `w × diff_height` pixels: all 15-bit = `2 × block_size` bytes
- So `sptr_end ≤ tmpblock + 2 × block_size < tmpblock + 3 × block_size`
- When `sptr = sptr_end - 1` and MSB=1: `AV_RB16` reads at `sptr_end`, which is within the allocated `tmpblock` (uninitialized region, but within the 3×block_size allocation)
- No true OOB past the heap allocation boundary

**2. `s->blocks` NULL dereference on OOM (lines 361, 237-239):**
- `av_mallocz` at line 361 has no error check
- If OOM → `s->blocks = NULL`
- The guard at line 451-455 only catches it when `zlibprime_curr || zlibprime_prev` is set
- If priming flags are 0 AND `is_keyframe` AND `size > 0`: reaches line 238 `s->blocks[blk_idx].pos = ...` → NULL deref crash
- BUT: requires genuine OOM — not externally triggerable from a crafted file alone

**3. Integer arithmetic:**
- `block_width/height`: 4-bit field → max 256; `block_size` max 65536; `3 × block_size` max 196608 — no overflow
- `image_width/height`: 12-bit → max 4095; `h_blocks × v_blocks` max 65025 — no overflow in `av_mallocz` size
- Palette index: `*sptr & 0x7F` (MSB=0 branch) → range 0–127; palette has 128 entries — within bounds

**4. All `memcpy` destinations:**
- Frame writes: bounded by `image_height × linesize`, math verified in-bounds
- `tmpblock` reads: bounded by `block_size × 3`
- `keyframe` buffer: allocated as `linesize × height`, accessed at same frame indices

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
