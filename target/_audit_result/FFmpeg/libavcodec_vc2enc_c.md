The analysis is complete. Key findings confirmed:

- `VC2_TRANSFORMS_NB = 7` (enum count = 7, valid indices 0–6)
- AVOption `wavelet_type` max = `VC2_TRANSFORMS_NB = 7` (inclusive per AV_OPT_TYPE_INT semantics) → allows index 7
- `ff_dirac_default_qmat[7][4][4]` has only 7 rows (0–6); index 7 is OOB
- `vc2_subband_dwt[VC2_TRANSFORMS_NB]` = 7-element array (0–6); index 7 is OOB function-pointer slot

## VULN: vc2enc AVOption off-by-one allows OOB read and invalid function-pointer call via wavelet_idx=7
- **漏洞类别**: memory-safety
- **函数**: `init_quant_matrix()` (lines 461–465, 475) and `dwt_plane()` (line 901)
- **行号**: 1207 (root cause), 461-465, 475, 901 (triggered sites)
- **CWE**: CWE-129 (Improper Validation of Array Index)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted encoder invocation with `-wavelet_type 7` option (or via libavcodec API)
- **外部触发路径**: `ffmpeg -i input -c:v vc2 -wavelet_type 7 out.vc2` → `vc2_encode_init()` (no check) → `vc2_encode_frame()` → `encode_frame()` → `dwt_plane()` line 901 `t->vc2_subband_dwt[idx](...)` with idx=7 (OOB); also `calc_slice_sizes()` → `init_quant_matrix()` → `ff_dirac_default_qmat[7][level][orientation]` (OOB read)
- **描述**: The AVOption definition for `wavelet_type` at line 1207 sets the inclusive maximum to `VC2_TRANSFORMS_NB` (= 7). However, both `ff_dirac_default_qmat[7][4][4]` (declared as 7 rows, valid indices 0–6) and `vc2_subband_dwt[VC2_TRANSFORMS_NB]` (7-element function-pointer array, valid indices 0–6) are indexed with `s->wavelet_idx` without a bounds guard. When `wavelet_idx = 7`: (1) `init_quant_matrix()` performs an OOB read of `ff_dirac_default_qmat[7][level][orientation]`, reading arbitrary static memory beyond the array. (2) `dwt_plane()` reads `t->vc2_subband_dwt[7]` which lies past the end of the `VC2TransformContext` struct (within the embedding `TransformArgs`), fetching whatever 8 bytes follow the struct as a function pointer, then calls it — yielding an invalid indirect call with attacker-influenced arguments.
- **触发条件**: An attacker who can control the vc2 encoder option `wavelet_type` (e.g., via `-wavelet_type 7` on the FFmpeg command line, or via `av_opt_set(enc_ctx, "wavelet_type", "7", ...)` through the libavcodec API in an application that exposes encoder configuration) and supplies any video frame (arbitrary content) as input.
- **安全影响**: In release builds (assertions disabled), the invalid function-pointer call at line 901 executes an arbitrary address derived from heap/struct memory, leading to a crash (DoS) or, under exploitation, arbitrary code execution (RCE). The OOB read in `init_quant_matrix` additionally leaks static memory contents into the `s->quant` table (information disclosure).

<!-- AUDIT_PROMPT_VERSION: 1 -->
