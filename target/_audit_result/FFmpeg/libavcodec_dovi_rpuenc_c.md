I have confirmed the key vulnerability. Let me write the final report.

## VULN: Heap Buffer Overflow in ff_dovi_rpu_generate() via Underestimated MMR Mapping Buffer Size
- **漏洞类别**: memory-safety
- **函数**: ff_dovi_rpu_generate()
- **行号**: 782-795, 863-869
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (HEVC or AV1 with embedded Dolby Vision RPU)
- **外部触发路径**: ffmpeg -i crafted.hevc -c:v libx265 out.hevc → ff_dovi_configure() → ff_dovi_rpu_generate() → buffer_size underestimated at line 783 → av_fast_padded_malloc allocates too-small buffer at line 792 → put_se_coef() writes beyond allocated heap buffer at lines 863-869
- **描述**: 在 `ff_dovi_rpu_generate()` 的 buffer_size 预估阶段（第 782–786 行），每个 MMR 映射段的写入代价被硬编码为 177 字节，每个多项式段为 26 字节。实际写入量由 `hdr->coef_log2_denom`（合法范围 0–62）决定：对于 MMR order=3 的一个段，实际写入为 23 个 `put_se_coef` 调用（每调用写 `set_se_golomb(coef>>D)` + `put_bits63(D, frac)` 共最多 31+D bits）再加 2 位的 order 字段，共 `23*(31+D)+2` bits。当 `D=48` 时，单段实际写入约 228 字节，超过估值 177 字节 51 字节/段。对于 3 条曲线各 8 个 pivot（即 24 个 MMR 段），总溢出约 1224 字节，远超 `av_fast_padded_malloc` 附加的 64 字节 padding（`AV_INPUT_BUFFER_PADDING_SIZE=64`），导致约 1160 字节的堆外写入，覆盖相邻堆块。`init_put_bits(pb, s->rpu_buf, s->rpu_buf_sz)` 初始化后，`put_bits`/`put_bits63` 不做边界检查，直接以 `AV_WB32` 向缓冲区外写入。
- **触发条件**: 构造一个包含 Dolby Vision RPU 的 HEVC 或 AV1 文件，令 RPU 头中 `coef_data_type=RPU_COEFF_FIXED`，`coef_log2_denom≥28`（建议取 48 以最大化溢出），3 条 VDR 曲线各设 9 个 pivot（8 个区间），所有区间均使用 `AV_DOVI_MAPPING_MMR` 且 `mmr_order=3`，系数满足 `|coef >> coef_log2_denom| ≤ 0x7FFF` 以通过 `validate_mapping_for_generation()` 的校验。以该文件作为输入进行含 DV RPU 重新编码的转码操作（如 libx265/libsvtav1 输出）即可触发。
- **安全影响**: 堆缓冲区溢出约 1160 字节（以 `coef_log2_denom=48`、3×8 个 MMR-3 段为例），覆盖相邻堆对象的内容，攻击者可通过精心构造的 RPU 字节流控制写入数据（系数值）和写入偏移，最坏情况下可实现远程代码执行（RCE）；即使无法控制执行流，也可造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
