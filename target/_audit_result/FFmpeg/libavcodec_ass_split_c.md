I now have all the information needed for the analysis. Let me compile the key findings.

**Group 1 analysis (lines 1–200):** `convert_str` takes `int len`; `strcspn` assigns `size_t` → int. Truncation only dangerous at SIZE_MAX (multi-GB), not practical. `ff_ass_split_dialog` guards `len >= INT_MAX` but passes `len = INT_MAX-1` silently – `av_malloc(INT_MAX)` would just fail. No exploitable path here.

**Group 2 analysis (lines 201–260 – `realloc_section_array`):** Both `*count` (from `ASS.styles_count` / `ASS.dialogs_count`) and `section->size` (from `ASSSection.size`) are declared `int`. The expression `tmp += *count * section->size` is evaluated as `int × int` with no intermediate widening. On a 64-bit host where `av_realloc_array` succeeds (allocation guarded by `size_mult` overflow check at `size_t` level), if `*count` reaches `INT_MAX/section->size + 1`, the product wraps to a negative signed int, which sign-extends to a negative `ptrdiff_t`. The subsequent `memset(tmp, 0, section->size)` then writes below the allocated buffer. Threshold: `sizeof(ASSStyle) = 104` → ~20.6 M entries ≈ 1 GB file; `sizeof(ASSDialog) ≈ 64` → ~33.6 M entries ≈ 1.3 GB file.

**Group 3 analysis (lines 261–395 – section/order parsing):** `av_reallocp_array` failure path frees the intermediate `order` buffer but `ctx->field_order[X]` is set NULL via `av_mallocz`; line 303 only writes it after the loop; the `!order` guard prevents re-entry when non-NULL. No double-free reachable. `order[i]` values are clamped to 0–22 (field index within a 24-element static array). No OOB in `convert_func[]` access.

**Group 4 analysis (lines 396–590 – `ff_ass_split_override_codes`, `ff_ass_style_get`):** `text_len` counter is `int` but overflow requires >2 GB inline text. `buf++` advance logic is sound. No memory safety issues.

## VULN: signed-integer-overflow OOB write in realloc_section_array via excess Style/Dialog entries
- **漏洞类别**: memory-safety
- **函数**: realloc_section_array()
- **行号**: 213-226
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (MKV/Matroska with oversized ASS subtitle extradata)
- **外部触发路径**: `ffmpeg -i crafted.mkv -f null -` → `avformat_open_input()` → Matroska demuxer reads codec extradata → `ff_ass_split(extradata)` → `ass_split()` → `ass_split_section()` → `realloc_section_array()`
- **描述**: 在 `realloc_section_array()` 的第222行，`tmp += *count * section->size` 中 `*count`（`int`，来自 `ASS.styles_count` / `ASS.dialogs_count`）与 `section->size`（`int`，编译期固定值，如 `sizeof(ASSStyle)=104`）做乘法，结果类型为 `int`，未做宽度提升。当 `*count` 累积至 `INT_MAX / section->size + 1` 时（对 ASSStyle 约 20,643,920；对 ASSDialog 约 33,554,432），乘积发生有符号溢出（C 未定义行为），在二进制补码实现中产生负值。该负值经符号扩展为 `ptrdiff_t` 后用于指针运算，使 `tmp` 指向分配缓冲区起始地址之前约 2 GB 处；随后的 `memset(tmp, 0, section->size)` 将 `section->size` 字节写入该越界地址。关键点：`av_realloc_array` 在 `size_t` 层面正确处理了溢出（通过 `size_mult`），因此在 64 位系统内存充足时分配本身可以成功，但后续的 `int` 乘法不受此保护。
- **触发条件**: 构造一个 MKV（Matroska）文件，其 ASS 字幕流的 codec extradata（`[V4+ Styles]` 或 `[Events]` 节）包含超过约 2000 万行 `Style:` 或约 3300 万行 `Dialogue:` 条目，使 `styles_count` / `dialogs_count` 累加至溢出阈值。每行最短约 30–50 字节，触发文件总计约 600 MB–1.3 GB。
- **安全影响**: 最轻后果为进程因访问未映射内存而崩溃（DoS）。若攻击者能操控大型堆布局，使 `tmp - 2 GB` 落在有效已分配堆区域，则 `memset` 将在任意堆偏移处写入零字节，可能破坏相邻堆元数据或对象指针，进而在有利条件下导致远程代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
