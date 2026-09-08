I have all the information I need. Let me complete my analysis.

**Complete vulnerability chain:**

1. `vvc_extradata_to_annexb()`, line 49: `size_t new_extradata_size = 0;` — accumulates as `size_t`
2. Line 166–174: per NALU, adds `4 + nalu_len` to `new_extradata_size`. The check at line 162 guards only against `SIZE_MAX` overflow, **not** `INT_MAX`.
3. **Line 182**: `ctx->par_out->extradata_size = new_extradata_size;` — silent **truncation** from `size_t` to `int`. If `new_extradata_size` ∈ (INT\_MAX, 2³²), the result is a **negative int**.
4. In `vvc_mp4toannexb_filter()`, line 285: `extra_size = add_extradata * ctx->par_out->extradata_size;` — `extra_size` becomes negative.
5. **Line 288 check bypassed**: `FFMIN(INT_MAX, SIZE_MAX) < 4ULL + nalu_size + extra_size`. When `extra_size` (negative int) is sign-extended to `uint64_t`, unsigned wrap-around makes the sum appear small and ≤ INT\_MAX, so the guard does **not fire**.
6. **Line 295**: `av_grow_packet(out, 4 + nalu_size + extra_size)` allocates only `nalu_size - |extra_size| + 4` bytes (far less than the real extradata size).
7. **Line 299–300**: `if (extra_size) memcpy(out->data + prev_size, ctx->par_out->extradata, extra_size)` — negative `int` → `size_t` promotion yields ≈ 2⁶⁴ − |extra\_size| bytes copied into the undersized buffer → **heap buffer overflow**.

**Concrete trigger**: vvcC box ≈ 2 GB with many tiny (nalu\_len = 1) NALUs causes output extradata ≈ 3.5 GB (>INT\_MAX), truncating `extradata_size` to ~−536 870 912. A subsequent IRAP packet of ~2 GB satisfies the wrap-around condition at line 288.

## VULN: size_t-to-int truncation of extradata_size leads to heap buffer overflow via negative memcpy size
- **漏洞类别**: memory-safety
- **函数**: vvc_extradata_to_annexb() / vvc_mp4toannexb_filter()
- **行号**: 182 (truncation site); 285, 288, 295, 299-300 (exploitation site)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (VVC/MP4 container)
- **外部触发路径**: `ffmpeg -i crafted_vvc.mp4 -f null -` → `avformat_open_input()` → VVC demuxer sets oversized `extradata` → `ff_vvc_mp4toannexb_bsf` BSF init → `vvc_mp4toannexb_init()` → `vvc_extradata_to_annexb()` [line 182: `size_t new_extradata_size` silently truncated to negative `int extradata_size`] → `vvc_mp4toannexb_filter()` [line 285: negative `extra_size`; line 288: overflow-check bypassed via uint64 wrap; line 300: `memcpy(..., extra_size)` with huge `size_t`]
- **描述**: In `vvc_extradata_to_annexb()`, the accumulator `new_extradata_size` is declared as `size_t` (64-bit) and guarded only against `SIZE_MAX` wrap (line 162). When the crafted vvcC box causes the total output size to exceed `INT_MAX` but remain below `2^32`, the assignment `ctx->par_out->extradata_size = new_extradata_size` at line 182 silently truncates to a negative `int`. In the subsequent filter call, `extra_size` inherits this negative value (line 285). The overflow guard at line 288 uses `4ULL + nalu_size + extra_size` — the sign-extended negative `extra_size` wraps uint64 arithmetic to a small positive value, bypassing the check. `av_grow_packet` is then called with a reduced size (`nalu_size − |extra_size| + 4`), allocating far too little memory. The `if (extra_size)` branch at line 299 fires (non-zero), and `memcpy` at line 300 receives `extra_size` as the `size_t` count parameter; negative int → size_t yields ~2⁶⁴ − 500 MB, writing far past the allocated heap buffer.
- **触发条件**: 攻击者需构造一个 MP4/VVC 文件，其 vvcC box 包含约 2 GB 的 extradata（由大量 nalu\_len=1 的微小 NALU 组成，利用每 NALU +4 字节 startcode 开销使输出超过 INT\_MAX），随后在同一文件中放置一帧约 2 GB 的 IRAP 帧，使得过滤器 filter 调用中 `nalu_size` 足够大，触发 line 288 的 uint64 绕过条件。
- **安全影响**: 最坏情况下，攻击者可控写入超大量字节到堆上 `out->data` 之后的内存区域，造成堆破坏；结合适当的堆布局可实现任意代码执行（RCE）。即使无法精确控制写入内容，也必然导致进程崩溃（DoS）。受影响的任何将 VVC 媒体文件 BSF 过滤链接起来的流水线（含 Web 视频转码服务）均可被远程利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
