## VULN: Heap OOB Write in d3d12va_encode_h264_init_picture_params via Undersized pd Array
- **漏洞类别**: memory-safety
- **函数**: d3d12va_encode_h264_init_picture_params()
- **行号**: 485-525
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted encoding invocation (Windows D3D12VA H.264 encoder)
- **外部触发路径**: ffmpeg -i <input> -c:v h264_d3d12va -bf 2 <output> -> ff_d3d12va_encode_receive_packet() -> d3d12va_encode_h264_init_picture_params() -> OOB write to pd[]
- **描述**: 在 `d3d12va_encode_h264_init_picture_params()` 第 485 行，`pd` 通过 `av_calloc(MAX_PICTURE_REFERENCES, sizeof(*pd))` 分配，仅有 `MAX_PICTURE_REFERENCES = 2` 个元素（`hw_base_encode.h:27`）。随后两段循环——List0 引用帧（第 494–505 行）和 List1 引用帧（第 514–525 行）——共享同一累积索引变量 `idx`，并持续写入 `pd[idx]`。当编码 B 帧时，若 `nb_refs[0] + nb_refs[1] > 2`（例如 List0 有 2 个引用帧、List1 有 1 个），第二段循环第一次迭代就会执行 `pd[2].ReconstructedPictureResourceIndex = idx`，越界写堆块，造成 heap OOB write。`nb_refs[0]` 和 `nb_refs[1]` 各自最大为 `MAX_PICTURE_REFERENCES = 2`，所以总计最多可触发对 `pd[2]`/`pd[3]` 的越界写入，超出分配大小 2×sizeof(descriptor) 字节。
- **触发条件**: 攻击者（或受害用户）在支持 D3D12VA 的 Windows 系统上，使用 `h264_d3d12va` 编码器对含 B 帧的视频进行转码，且基础编码上下文为 B 帧分配了 List0 引用 ≥ 1 且 List1 引用 ≥ 1 且两者之和 > 2（如 `-bf 3` 并配置多参考帧），即可触发；无需特殊权限，任何拥有 D3D12 硬件的普通用户均可触发。
- **安全影响**: 堆内存越界写入，攻击者若能控制 `nb_refs[]` 数量或相邻堆布局，可实现任意写原语，最坏情况导致远程/本地代码执行（RCE）；至少可造成可靠的进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
