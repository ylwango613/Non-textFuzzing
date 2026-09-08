`MAX_PICTURE_REFERENCES = 2`, so `nb_refs[0] + nb_refs[1] ≤ 4`, total barrier writes ≤ 5, well inside the 16-element `barriers_ref` buffer. The texture-array allocation matches `initial_pool_size * plane_count` and iterates over exactly `DepthOrArraySize * plane_count` entries (same value after `av_hwframe_ctx_init`). All dimension arithmetic is bounded by D3D12 hardware limits (≤16384 per axis), which precludes integer overflow in `3 * w * h`. `meta->EncodedBitstreamWrittenBytesCount` originates from the D3D12 driver, not from a crafted bitstream. Every `av_calloc` path has internal overflow checking. This file is encoder-only code; no externally-supplied compressed bitstream data flows into memory-allocation sizes.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
