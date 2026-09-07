I have now thoroughly analyzed the entire file. Let me write the final report.

The single confirmed memory-safety bug is the stack buffer over-read in `DecryptSampleData` at lines 210-214. The `chunk` variable is set to `offset` (= `bso%16`, up to 15) instead of the correct `16-offset`, so the loop accesses `zero_enc[offset+i]` up to index `2*offset-1 = 29` while `zero_enc` is only 16 bytes. For offset ∈ {9..15} (attacker-controlled via the sample IV field) the read exceeds the array boundary, leaking up to 14 bytes of neighboring stack memory (including `iv[16]`, `bso` value) into the decrypted output buffer `out`.

The `GetDecryptedSampleSize` integer underflow (line 138) is real but its return value is only used for mdat-size metadata in the Processor (via the 64-bit `mdat_payload_size`), not for any buffer allocation, so it does not constitute a direct memory-safety hazard on the mp42aac path.

## VULN: Stack OOB Read in DecryptSampleData via Malformed IV
- **漏洞类别**: memory-safety
- **函数**: AP4_IsmaCipher::DecryptSampleData()
- **行号**: 207-214
- **CWE**: CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 4.7 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → MP4 box parsing → iAEC protected sample → AP4_IsmaCipher::DecryptSampleData() [line 144] → inner block-alignment branch [line 203] → OOB loop [line 213]
- **描述**: `zero_enc` 是 16 字节的栈数组（第 208 行）。`offset = bso % 16`（取值 0–15），但 `chunk` 被错误设置为 `offset` 而非正确值 `16 - offset`。循环 `for (i=0; i<chunk; i++) out[i] = zero_enc[offset+i] ^ in[i]` 中，`offset+i` 的最大下标为 `2*offset - 1`。当 `offset ≥ 9` 时（如 offset=15 最大下标=29）超出 `zero_enc[16]` 边界，读取栈上相邻变量（`iv[16]`中含 AES-CTR 初始向量等敏感数据）并将其与明文 XOR 后写入解密输出缓冲区 `out`，从而发生栈内存泄露。
- **触发条件**: 攻击者构造 ISMA 保护方案（`iAEC`）的 MP4 文件，在 sample 的 IV 字段设置使 `bso % 16` 落在 9–15 范围内（例如将 8 字节 IV 的最低位设置为 0x0F），同时 payload_size ≥ offset，使 chunk 不被截断。
- **安全影响**: 栈内存（最多 14 字节，含 AES-CTR IV 及相邻栈帧数据）泄露到解密输出文件；若攻击者能读取输出 .aac 文件，则可提取 IV 等密钥材料。后续解密阶段因跳字节数错误可能导致程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
