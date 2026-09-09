The analysis is complete. I found a confirmed heap out-of-bounds write in `ff_vp3dsp_set_bounding_values`:

- `bounding_values_array` in `VP56Context` (vp56.h:171) is declared as **256 ints** only.
- The function sets `bounding_values = bounding_values_array + 127`, then unconditionally writes to `bounding_values[129]` through `bounding_values[132]` (x86) — which map to `bounding_values_array[256..259]`, all out-of-bounds.
- The immediately adjacent struct field (`coeff_ctx[4][64]`, vp56.h:173) is overwritten.
- By contrast, `vp3.c` correctly declares `[256 + 4]` elements (line 325), so only the VP56 path is vulnerable.

---

## VULN: Heap OOB Write in ff_vp3dsp_set_bounding_values via VP56 Context
- **漏洞类别**: memory-safety
- **函数**: ff_vp3dsp_set_bounding_values()
- **行号**: 477-503
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file
- **外部触发路径**: ffmpeg -i <crafted_vp6.flv> -f null - → avformat_open_input() → av_read_frame() → vp56_decode_frame() → ff_vp56_init_dequant() [vp56.c:39] → ff_vp3dsp_set_bounding_values(s->bounding_values_array, ...) [vp3dsp.c:477] → unconditional write to bounding_values[129..132] → heap OOB write into adjacent VP56Context.coeff_ctx
- **描述**: 在 `ff_vp3dsp_set_bounding_values` 中，局部指针 `bounding_values = bounding_values_array + 127`。函数在最后无条件地写入 `bounding_values[129]`、`[130]`（非x86）以及 `[131]`、`[132]`（x86，见第498-501行），分别对应 `bounding_values_array[256..259]`。而当该函数由 `ff_vp56_init_dequant`（vp56.c:39）调用时，传入的 `s->bounding_values_array` 在 `VP56Context`（vp56.h:171）中被声明为 `int bounding_values_array[256]`，有效索引范围为 [0, 255]。因此对索引 256~259 的写入越过数组末尾，直接覆盖紧随其后的结构体字段 `coeff_ctx[4][64]`（vp56.h:173），造成堆内存破坏。对比之下，`vp3.c` 中正确分配了 `[256+4]` 元素（第325行），VP56 路径漏掉了这4个额外元素，属于遗漏修复。写入的值为 `filter_limit * 0x00020002U`（x86）或 `filter_limit * 0x02020202U`（非x86），而 `filter_limit` 由 `ff_vp56_filter_threshold[quantizer]` 查表得到，quantizer 直接来自 VP5/VP6 比特流，攻击者可通过选取不同 quantizer 控制写入值的范围（0~127×常数）。
- **触发条件**: 攻击者构造包含 VP5 或 VP6 编码视频流的媒体文件（如 .flv、.avi）。每当解码器处理量化参数（quantizer）变化时（即调用 `ff_vp56_init_dequant`），均会触发该越界写入；首帧即可触发，无需特殊帧序列。
- **安全影响**: 堆上相邻结构体字段 `coeff_ctx` 被覆盖，可导致后续解码逻辑使用被污染的系数上下文数据，进而引发进一步内存损坏。在最坏情况下，利用该写入原语配合堆风水（heap feng shui）可实现任意代码执行（RCE）；在一般情况下至少可导致程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
