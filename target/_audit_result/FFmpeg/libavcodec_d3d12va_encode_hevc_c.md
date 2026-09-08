I have completed my analysis. The complete file was read in two passes and key context (hw_base_encode.h, hw_base_encode.c, d3d12va_encode.c) was checked. Here is the confirmed finding:

---

**Analysis summary of the OOB write:**
- `pd` is allocated at line 622 with exactly `MAX_PICTURE_REFERENCES = 2` entries.
- The combined index `idx` accumulates across both the list0 loop (lines 631–643) and the list1 loop (lines 652–664).
- `hw_base_encode.c:52–57` confirms `nb_refs[0]` can reach 2 while `nb_refs[1]` = 1 (joint assertion `nb_refs[0] < 2 && nb_refs[1] < 2` allows the path `(1,0)→(2,0)→add list1→(2,1)` before any abort).
- For a B-frame with `nb_refs[0]=2, nb_refs[1]=1`, `idx` reaches 3: `pd[2]` and beyond are written — past the two-element allocation — corrupting the heap.

---

## VULN: Heap OOB Write in d3d12va_encode_hevc_init_picture_params via Undersized pd Array
- **漏洞类别**: memory-safety
- **函数**: d3d12va_encode_hevc_init_picture_params()
- **行号**: 622-664
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted encoder invocation / transcoding pipeline
- **外部触发路径**: ffmpeg -hwaccel d3d12va -i input.mp4 -c:v hevc_d3d12va -bf 1 -refs 2 output.mp4 -> ff_d3d12va_encode_receive_packet() -> d3d12va_encode_issue() -> d3d12va_encode_hevc_init_picture_params() -> heap OOB write at pd[idx] where idx >= 2
- **描述**: 在 `d3d12va_encode_hevc_init_picture_params()` 函数中，第 622 行以 `MAX_PICTURE_REFERENCES = 2` 分配了 `pd` 数组（`av_calloc(MAX_PICTURE_REFERENCES, sizeof(*pd))`，仅 2 个元素）。list0 循环（第 631–643 行）和 list1 循环（第 652–664 行）共用一个累加索引 `idx`：list0 循环结束后 `idx = nb_refs[0]`，list1 循环从该值继续，最终 `idx = nb_refs[0] + nb_refs[1]`。当编码 B 帧且 `nb_refs[0] + nb_refs[1] > 2`（例如 `nb_refs[0]=2, nb_refs[1]=1`，即 3 个总引用帧）时，list1 循环中对 `pd[2]`、`pd[3]` 的写入超出分配边界，造成堆溢出。`hw_base_encode.c` 中的断言（第 52–53 行）仅逐列表限制（各自 < 2），允许两个列表合计达到 3，不能阻止此越界。
- **触发条件**: 使用 D3D12VA HEVC 编码器（`hevc_d3d12va`）配合 B 帧（`-bf 1` 或默认 `bf=2`）和多个前向参考帧（`-refs 2`）编码视频，使某一 B 帧的 `nb_refs[0] + nb_refs[1] >= 3`，即可触发该漏洞。输入视频文件本身不需要畸形构造；任何能驱动此编码配置的媒体文件均可触发。
- **安全影响**: 堆越界写入（写入至少一个完整的 `D3D12_VIDEO_ENCODER_REFERENCE_PICTURE_DESCRIPTOR_HEVC` 结构体，约 12 字节）造成堆内存破坏，在精心控制堆布局的条件下可实现任意代码执行（RCE）；最低造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
