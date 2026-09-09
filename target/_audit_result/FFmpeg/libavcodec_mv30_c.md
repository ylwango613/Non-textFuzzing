Complete analysis summary:

**decode_coeffs (lines 379–403):** `nb_codes` is max 65535 (16-bit read), `sizeof(int16_t)=2`, allocation = 131070 bytes + padding. The write `coeffs[i++]=x` is guarded by `i < nb_codes` at loop entry. The "else" skip-run branch can only overshoot `i` beyond `nb_codes`, causing loop exit — no write occurs past the allocated buffer. No OOB.

**mvectors allocation (line 492):** `2 * s->nb_mvectors` max = 131070; × 2 = 262140 bytes. No integer overflow. The bytestream2 safely returns 0 past end. No OOB.

**Height non-alignment issue:** Mitigated by `h_align=32` in `avcodec_align_dimensions2` (pool always allocates `FFALIGN(height,32)` rows). Maximum decoder row access `= 16*floor((h−1)/16)+8`, provably < `FFALIGN(h,32)` for all h.

**Motion vector bounds check (lines 557–558):** `py ≤ FFALIGN(height,16)−16`, so `py+8 ≤ FFALIGN(height,16)−8 < FFALIGN(height,32)` = pool allocation. No OOB read from prev_frame.

**VLC values:** `get_vlc2` returns 0..11 (12-entry cbp_tab). `1 << 11 = 2048`. No integer overflow in `decode_coeffs` arithmetic.

**All other paths** (pfill accumulation, bytestream2 reads, skip_bits_long, zigzag indexing, block[6][64] accesses) are bounded by constants or safely clamped by the bitstream reader API.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
