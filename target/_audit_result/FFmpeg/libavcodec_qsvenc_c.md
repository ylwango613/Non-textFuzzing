After reading all 2767 lines of `qsvenc.c` in 6 batches, examining the header file, related structures, and conducting targeted searches for all `av_malloc`/`memcpy`/size computations, I have completed the analysis.

Key findings during the audit:

1. **`packet_size` integer overflow** (lines 1306, 1510): `BufferSizeInKB * BRCParamMultiplier * 1000` — these are `mfxU16` values returned from the MFX runtime, not from user-controlled media file data. Even if overflow occurred, `MaxLength=0` would be sent to MFX which would then fail-safe.

2. **MJPEG fallback `packet_size`** (line 1310): `Height * Width * 4` — theoretically overflows int at ~23K×23K resolution. However, QSV hardware enforces dimension limits far below this during `MFXVideoENCODE_Query` in `check_enc_param()`. Hardware rejection prevents this path from being triggered.

3. **`qsvenc_get_continuous_buffer` `total_size`** (lines 1983–2021): `int total_size` computation for NV12/P010/BGRA overflow at very large dimensions. Same hardware enforcement argument applies; these dimensions can't pass the MFX init check.

4. **`extparam_internal` array bounds**: Carefully counted all 11 potential write sites against the formula `5 + (QSV_HAVE_MF*2) + (QSV_HAVE_EXT_AV1_PARAM*2) + QSV_HAVE_HE`. Maximum entries written (6) never exceeds array size (7 on the tightest platform). `QSV_HAVE_OPAQUE` (which adds one entry at line 1581) is mutually exclusive with both `QSV_HAVE_MF` (which adds 2 to the array size) and `QSV_HAVE_EXT_AV1_PARAM` (which adds 2), so the bounds hold.

5. **`update_parameters` ExtParam writes** (lines 2609–2620): Mathematical analysis confirms that total elements written equals exactly `q->nb_extparam` (the allocated size): first loop writes B elements, second loop writes A−m elements, total = A+B−m = `q->nb_extparam`.

6. **`extradata` allocation** (lines 1519–1537): `SPSBufSize`, `PPSBufSize`, `VPSBufSize` are bounded by the fixed-size stack buffers (512, 128, 128 bytes) declared just above. No overflow.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
