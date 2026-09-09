After a thorough multi-pass analysis of all 1331 lines of `vc1.c` plus its related header/data/decoder files, here is my assessment:

**Batch 1 (lines 1–450):** `bitplane_decoding`, `decode_rowskip`, `decode_colskip`, `vop_dquant_decoding`, `ff_vc1_decode_sequence_header`, `decode_sequence_header_adv`. No OOB found — all planep offset arithmetic is correctly bounded by stride × height; all VLC table indices are within declared array sizes.

**Batch 2 (lines 450–900):** `ff_vc1_decode_entry_point`, `rotate_luts`, `read_bfraction`, `ff_vc1_parse_frame_header`. `read_bfraction` checks only index 21 (invalid sentinel) and allows 22 (BI-frame sentinel, `ff_vc1_bfraction_lut[22]` = 0, array size 23) — by design, not a bug. All VLC table index widths (get_bits widths: 2, 3, 5 bits) match declared array sizes exactly.

**Batch 3 (lines 900–1331):** `ff_vc1_parse_frame_header_adv`. All VLC index reads are bounded: `icbptab = get_bits(3)` → 0–7, `ff_vc1_icbpcy_vlc[8]`; `imvtab = get_bits(2 + numref)` with numref ∈ {0,1} → correct branch to `ff_vc1_1ref_mvdata_vlc[4]` / `ff_vc1_2ref_mvdata_vlc[8]`; `mbmodetab = get_bits(3)` → `ff_vc1_if_mmv_mbmode_vlc[8]` / `ff_vc1_if_1mv_mbmode_vlc[8]`, all within bounds.

**Buffer allocation cross-check:** Bitplane buffers allocated as `mb_stride * FFALIGN(mb_height, 2)` (vc1dec.c:363–371). `mbskip_table` allocated as `FFALIGN(mb_height,2)*mb_stride + 2` (mpegvideo.c:224–230). `s->height` fixed at init time (mpegvideo_dec.c:94), so in-stream entry-point dimension changes cannot inflate `height` used in `bitplane_decoding`. All access patterns stay within their allocated regions.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
