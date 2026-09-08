**Analysis summary:**

The file contains pure IDCT math transforms (`ff_h264_idct_add`, `ff_h264_idct8_add`, the dc-only variants, and the multi-block dispatchers `add16`, `add16intra`, `idct8_add4`, `add8`, `add8_422`, plus the dequant-IDCT functions). Every loop bound is compile-time constant (4, 8, 16 iterations). Key checks:

- **`scan8[]` indexing**: In all dispatch functions the highest index into `scan8` is 43 (`ff_h264_idct_add8_422`, second loop, `scan8[i+4]` with i=39). The array is 51 elements. Max value returned is `scan8[43]=103`, which is within every `nnzc` array (`15*8=120` or `5*8=40` for the appropriate functions). ✓
- **`block_offset[]` indexing**: Max index is 43 (same function). `h->block_offset` is `int[96]`. Even for the field-MB case (starting at index 48), `48+43=91 < 96`. ✓
- **`block + i*16*sizeof(pixel)` pointer arithmetic**: `sl->mb` is `int16_t[16*48*2]=int16_t[1536]`. Highest offset is `39*16*sizeof(pixel)`. For 8-bit: +624 int16_t; for 16-bit (dctcoef=int32_t): +1248 int16_t. Each called function accesses 16 dctcoef elements past the base. All within the 3072-byte buffer. ✓
- **`luma_dc_dequant_idct` output**: Max write index = `stride*5 + x_offset[3]` = `16*5+160=240` dctcoef. `sl->mb` holds at least 768 usable int32_t elements (high-depth) or 1536 int16_t (8-bit). ✓
- **`stride` computation** (`stride >>= sizeof(pixel)-1`): stride values come from internally-computed frame line sizes, not attacker-controlled container fields. ✓

No attacker-controlled field flows into any allocation size or array index; all loops are statically bounded; all buffer sizes have been verified against the declared `sl->mb[1536]` and `h->block_offset[96]` arrays.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
