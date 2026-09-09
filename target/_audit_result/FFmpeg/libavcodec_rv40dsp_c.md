Analysis complete. I have identified a confirmed OOB read vulnerability. The critical path:

- `rv40.c:465`: `dither = j ? ij : i*4` — with `j=12, i=3` produces `dither=15`
- This is passed as `dmode` to `rv40_adaptive_loop_filter` → `rv40_strong_loop_filter`
- Inside `rv40_strong_loop_filter` (rv40dsp.c:521,525,533,535): `rv40_dither_l[dmode+i]` and `rv40_dither_r[dmode+i]` where `i` runs 0..3
- Arrays `rv40_dither_l[16]` and `rv40_dither_r[16]` are 16 elements each (indices 0..15)
- `dmode=15, i≥1` → indices 16,17,18: out-of-bounds reads

## VULN: OOB Read in rv40_strong_loop_filter via dmode Array Overrun
- **漏洞类别**: memory-safety
- **函数**: rv40_strong_loop_filter()
- **行号**: 519-535
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted RV40 media file
- **外部触发路径**: ffmpeg -i <crafted.rv4> -f null - -> avformat_open_input() -> rv40_decode_frame() -> rv40_loop_filter() -> rv40_adaptive_loop_filter(dmode=15) -> rv40_strong_loop_filter(dmode=15) -> rv40_dither_l[15+1..3] OOB read
- **描述**: In `rv40_strong_loop_filter()` (rv40dsp.c), the static arrays `rv40_dither_l[16]` and `rv40_dither_r[16]` are indexed as `rv40_dither_l[dmode + i]` where `i` iterates 0..3 in an inner loop (line 521, 525, 533, 535). The caller in `rv40_loop_filter()` (rv40.c:465) computes `dither = j ? ij : i*4` with outer loop `j ∈ {0,4,8,12}` and inner `i ∈ {0,1,2,3}`, yielding a maximum `dither` value of 15 (when j=12, i=3). This value becomes `dmode` passed to `rv40_strong_loop_filter`. When `dmode=15` and the inner filter loop reaches iterations i=1,2,3, the indices become 16, 17, 18 — beyond the 16-element arrays. Similarly `dmode=14` causes OOB at i=2,3 and `dmode=13` causes OOB at i=3. These are reads from adjacent `.rodata` memory after the array bounds.
- **触发条件**: Attacker crafts an RV40 (.rv4) video file with an intra-coded macroblock (or MB with separate DCs, setting `mb_strong=1`) positioned such that the luma deblocking loop iterates to j=12 and i=3. The strong filter path is activated when `rv40_loop_filter_strength` returns non-zero, which is reachable when the codec's deblocking filter examines adjacent intra MB boundaries. No special build options are needed; this is the default C reference path.
- **安全影响**: Out-of-bounds read from static `.rodata` memory past `rv40_dither_l`/`rv40_dither_r`. On most platforms, adjacent `.rodata` pages are mapped (containing other codec constants), so the OOB read does not crash but yields garbage dither values that corrupt the decoded frame. In edge-case memory layouts where the pages following `.rodata` are unmapped, it can cause a SIGSEGV, enabling a DoS. Additionally, the OOB bytes are incorporated into computed pixel values written back to the frame buffer, which is a form of information disclosure from process static memory into decoded video output.

<!-- AUDIT_PROMPT_VERSION: 1 -->
