I now have all the information needed. The vulnerability is confirmed at line 214 in `Ap4IsmaCryp.cpp`. The `zero_enc[16]` stack buffer is accessed out-of-bounds when `bso%16 >= 9`, since the loop reads `zero_enc[offset + i]` where `offset + i` can reach up to `2*offset - 1 = 29` — 14 bytes past the end of the 16-byte array.

Attack path (with `--key`): `main()` → `DecryptAndWriteSamples()` → `AP4_SampleDecrypter::Create()` → `AP4_IsmaCipher::CreateSampleDecrypter()` → per-sample `AP4_IsmaCipher::DecryptSampleData()` [OOB at line 214].

The ISMACryp `iv_length` field in the iSFM atom is read directly from the MP4 file (stored as `AP4_UI08`, 0–255) and is not range-checked before being used. When `iv_length` is set to 1–8 and the sample IV is crafted to make `bso % 16 ≥ 9`, the loop overruns the 16-byte `zero_enc` stack array, leaking adjacent stack bytes (frame pointer, return address, local variables) into the decrypted output.

## VULN: ISMACryp DecryptSampleData Stack Buffer Over-Read via Crafted IV
- **漏洞类别**: memory-safety
- **函数**: AP4_IsmaCipher::DecryptSampleData()
- **行号**: 208-215 (Ap4IsmaCryp.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac --key \<any 16-byte hex\> crafted.mp4 out.aac → main() → DecryptAndWriteSamples() → AP4_SampleDecrypter::Create(pdesc, key, 16) [scheme=AP4_PROTECTION_SCHEME_TYPE_IAEC] → AP4_IsmaCipher::CreateSampleDecrypter() → per-sample loop → AP4_IsmaCipher::DecryptSampleData() → zero_enc[offset+i] OOB read at line 214
- **描述**: 在 `AP4_IsmaCipher::DecryptSampleData`（Ap4IsmaCryp.cpp:208-215）中，针对 Byte-Stream-Offset（`bso`）非 16 字节对齐的情况，代码分配了 16 字节的栈缓冲区 `zero_enc[16]`，将其填满后通过循环 `out[i] = zero_enc[offset+i]^in[i]` 对 `offset = bso%16`、`i ∈ [0, chunk-1]`（`chunk = min(offset, payload_size)`）进行索引。当 `offset ≥ 9` 时，最大索引 `offset + (offset-1) = 2*offset-1 ≥ 17`，超出 `zero_enc[0..15]` 合法范围，越界读取栈上相邻数据（最多 14 字节），并将其 XOR 入解密输出。`iv_length`（来自 iSFM atom）和样本 IV（来自媒体数据）均由攻击者完全控制，不存在任何上界校验。
- **触发条件**: 构造 ISMACryp 加密的 MP4 文件：在 iSFM atom 中设置 `iv_length = 1`（或 2–8），在样本数据中将 IV 第一字节设为 9–15（使 `bso % 16 ≥ 9`），确保 `payload_size ≥ offset`。然后以任意 16 字节 key 运行 `mp42aac --key <hex32> crafted.mp4 out.aac` 即可触发。
- **安全影响**: 栈上紧邻 `zero_enc` 的数据（帧指针、返回地址、局部变量等）最多 14 字节被泄漏进输出 `.aac` 文件，可用于绕过 ASLR 或泄露栈 canary，从而为进一步利用（链式 RCE）铺路；若 mp42aac 作为服务或流水线处理不可信 MP4 文件，可实现远程信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
