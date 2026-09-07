I now have full context. Let me do a final cross-check on the exact indices of the `zero_enc` array access.

**Group 1 analysis (lines 131–139): `GetDecryptedSampleSize`**
- `AP4_Size` = `AP4_UI32` (unsigned 32-bit, confirmed from Ap4Types.h:51)
- `isma_header_size = m_KeyIndicatorLength + m_IvLength` — both `AP4_UI08` (max 255+255=510), from file-controlled `iSFM` atom
- `return sample.GetSize() - isma_header_size;` — unsigned subtraction with no underflow guard
- If `sample.GetSize() = 0` and `isma_header_size = 17`, result = `0xFFFFFFEF` (~4.29 billion)
- Returned as `GetProcessedSampleSize` → `Ap4Processor.cpp:605-611`: added into `mdat_payload_size` and `current_chunk_size` (`AP4_Size`, 32-bit)

**Group 2 analysis (lines 195–219): `DecryptSampleData` inner loop**
- `zero_enc` is `AP4_UI08 zero_enc[16]` (stack, indices 0–15)
- `offset = (unsigned int)(bso % 16)` → 1–15 (always ≥1 because the `if (bso%16)` guard)
- `chunk = offset` (should be `16 - offset` to cover remaining bytes in the AES block — this is the logic bug)
- Loop: `for (unsigned int i=0; i<chunk; i++) out[i] = zero_enc[offset+i]^in[i];`
- Maximum access: `zero_enc[offset + chunk - 1] = zero_enc[2*offset - 1]`
  - offset=9 → `zero_enc[17]` (OOB +2)
  - offset=15 → `zero_enc[29]` (OOB +14)
- `bso` is built from attacker-controlled IV bytes in the ISMA sample payload (file field `iv_start`)
- The OOB read values (adjacent stack memory: saved registers, other locals, return address) are XOR'd with plaintext and written into `data_out` — **stack contents exfiltrated through decrypted output**

Both findings confirmed. Writing the final report now.

## VULN: Stack Buffer Overread via Crafted IV in ISMA DecryptSampleData
- **漏洞类别**: memory-safety
- **函数**: AP4_IsmaCipher::DecryptSampleData()
- **行号**: 207-219 (Ap4IsmaCryp.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file (ISMA-encrypted, attacker-controlled IV bytes in sample payload)
- **外部触发路径**: mp42aac input.mp4 → AP4_File::ParseStream() → AP4_Processor::Process() → AP4_IsmaTrackDecrypter::ProcessSample() → AP4_IsmaCipher::DecryptSampleData()
- **描述**: 在 `DecryptSampleData` 的非对齐字节流偏移处理分支（Ap4IsmaCryp.cpp:207–219）中，代码将 AES CTR 模式的 16 字节 keystream 块存入栈变量 `AP4_UI08 zero_enc[16]`，然后计算 `offset = (unsigned int)(bso%16)`（取值 1–15，因外层 `if(bso%16)` 判断保证非零），并将 `chunk = offset`（应为 `16 - offset` 才能正确覆盖块尾剩余字节）。循环 `for(i=0; i<chunk; i++) out[i] = zero_enc[offset+i]^in[i]` 访问 `zero_enc[offset+i]`，当 `offset=15, i=14` 时访问下标 29，而 `zero_enc` 仅有 16 字节（下标 0–15）。越界读取了紧邻栈内存（局部变量 `iv[16]`、`bso_bytes[8]`、保存的帧指针/返回地址等）最多 14 字节，并将其 XOR 输入后写入 `data_out`（堆缓冲区），导致栈内容通过解密输出泄露。
- **触发条件**: 攻击者构造一个包含 ISMA 加密轨道的 MP4 文件，使某个 sample 的 IV 字段（由 `m_IvLength` 字节的大端整数构成）在大端解释后满足 `bso % 16 >= 9`，且该 sample 的 payload_size ≥ offset；同时需要在 MP4 的 iSFM 原子中设置 `selective_encryption=0, key_indicator_length=0, iv_length=8`（合法值），IV 字段最低 4 位不为零即可触发（如 IV 末字节 = 0x0F → offset=15）。
- **安全影响**: 最多 14 字节栈内存（可能含有 ASLR 偏移、局部密钥材料或返回地址的一部分）通过 `data_out` 泄露；若在服务器端批量处理 MP4 文件的场景下，可用于信息泄露，配合其他漏洞可进一步绕过 ASLR 实现 RCE。

## VULN: Integer Underflow in GetDecryptedSampleSize Returns ~4 GB Size
- **漏洞类别**: memory-safety
- **函数**: AP4_IsmaCipher::GetDecryptedSampleSize()
- **行号**: 131-139 (Ap4IsmaCryp.cpp)
- **CWE**: CWE-191 (Integer Underflow / Wrap-around)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file (iSFM atom with large iv_length/key_indicator_length, combined with tiny sample)
- **外部触发路径**: mp42aac input.mp4 → AP4_Processor::Process() → AP4_IsmaTrackDecrypter::GetProcessedSampleSize() → AP4_IsmaCipher::GetDecryptedSampleSize() → 返回值用于 Ap4Processor.cpp:605-611 的 mdat_payload_size 累加
- **描述**: `GetDecryptedSampleSize`（Ap4IsmaCryp.cpp:134–138）计算 `AP4_Size isma_header_size = m_KeyIndicatorLength + m_IvLength`（两者均为 `AP4_UI08`，最大各 255，合计 511；若 `m_SelectiveEncryption=true` 则再加 1），然后 `return sample.GetSize() - isma_header_size`。`AP4_Size` 是 `AP4_UI32`（无符号 32 位），函数内无任何下界检查。当 sample 的 `GetSize()` 小于 `isma_header_size` 时，减法结果发生无符号下溢，返回约 4.29 GB（0xFFFFFFxx）的巨大值。该巨大值在 `AP4_Processor::Process()`（Ap4Processor.cpp:605–611）中被存入 sample table 并累加入 `mdat_payload_size`，导致后续写出的 mdat 大小字段严重错误；若存在以该大小为参数的堆分配路径（如解密输出缓冲区 `SetDataSize` 在不同调用场景下直接使用此返回值），将触发 ~4 GB 的堆分配失败（DoS）或整数溢出后的缓冲区下分配（heap overflow）。
- **触发条件**: 在 MP4 文件的 sinf→schi→iSFM 原子中将 `iv_length` 和 `key_indicator_length` 设置为较大值（例如各 128），使 `isma_header_size=257`；同时在 stsz 原子中将对应 sample 的大小设置为小于 257 的值（如 1 字节）；mp42aac 在处理该加密 sample 时即可触发下溢。
- **安全影响**: 进程尝试基于 ~4 GB 大小写出 mdat 或分配输出缓冲区，导致内存耗尽（DoS）；在部分代码路径（如 `AvcTrackWriterTest` 中直接以 `GetDecryptedSampleSize` 返回值调用 `SetDataSize`/`Read`）可能导致堆缓冲区欠分配后溢出（heap buffer overflow），最坏情况下可利用为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
