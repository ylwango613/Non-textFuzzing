Based on my analysis, the `Ap4IsfmAtom.h` / `.cpp` implementation itself is very simple (reads 3 bytes, stores them). The memory safety issue is in the downstream consumer `AP4_IsmaCipher::DecryptSampleData` in `Ap4IsmaCryp.cpp`, where `m_IvLength` from the iSFM atom controls a loop that reads out-of-bounds from a 16-byte stack array `zero_enc`. Let me verify the indexing one final time.

`zero_enc[16]` (valid indices 0–15). Loop: `for i in [0, chunk): out[i] = zero_enc[offset+i] ^ in[i]`. With `offset = bso%16` (0–15) and `chunk = min(offset, payload_size)`, the worst-case index is `offset + (chunk-1) = offset + offset - 1 = 2*offset - 1`. When `offset ≥ 9`, this exceeds index 15. Maximum access: `zero_enc[29]` when `offset=15`. This IS a stack OOB read.

## VULN: Stack OOB Read in DecryptSampleData via Crafted iSFM iv_length
- **漏洞类别**: memory-safety
- **函数**: AP4_IsmaCipher::DecryptSampleData()
- **行号**: 208-214 (Ap4IsmaCryp.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac --key \<key\> crafted.mp4 out.aac → main() → DecryptAndWriteSamples() → AP4_IsmaCipher::CreateSampleDecrypter() [reads m_IvLength from iSFM atom via AP4_IsfmAtom::Create()] → AP4_IsmaCipher::DecryptSampleData() → zero_enc[offset+i] OOB read
- **描述**: 在 `Ap4IsmaCryp.cpp` 的 `DecryptSampleData`（第208-214行）中，16字节栈数组 `AP4_UI08 zero_enc[16]` 在非块对齐路径下被越界读取。`offset = bso % 16`（范围0–15），循环 `for(i=0; i<chunk; i++) out[i] = zero_enc[offset+i] ^ in[i]` 中，`chunk` 初始值等于 `offset`，最大索引为 `offset + chunk - 1 = 2*offset - 1`。当 `offset ≥ 9` 时（即 `bso % 16 ≥ 9`），访问 `zero_enc[17]` 至 `zero_enc[29]`，最多越界读取14字节栈数据（`iv[16]`、`bso_bytes[8]`、`bso`、返回地址等）并将其混入解密输出。`m_IvLength` 来自 iSFM atom（`Ap4IsfmAtom.cpp:82` `stream.ReadUI08(m_IvLength)`），攻击者完全控制该字节；IV 字节来自样本数据，同样由攻击者控制，可精确设置 `bso % 16` 的值。
- **触发条件**: 攻击者构造包含 ISMA 加密音频轨道的 MP4 文件：(1) `iSFM` atom 中将 `iv_length` 字段设为 1–8（使 `m_IvLength <= 8` 分支生效）；(2) 样本数据中的 IV 字节使 `bso % 16 >= 9`（例如 iv_length=1，IV字节=0x09–0x0F）；(3) 用户使用 `--key` 参数运行 `mp42aac`（提供任意16字节密钥即可触发解密路径）。
- **安全影响**: 每个解密样本的输出中包含最多14字节的栈内存内容（可能包括 `iv[16]`、`bso_bytes[8]`、其他局部变量、保存的帧指针或返回地址），造成栈内存信息泄露；多个样本的输出可拼合出较大范围的栈布局信息，有助于绕过 ASLR 并为进一步利用提供基础。

<!-- AUDIT_PROMPT_VERSION: 1 -->
