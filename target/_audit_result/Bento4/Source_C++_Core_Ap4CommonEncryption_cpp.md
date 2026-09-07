I have now read the full file in batches and traced the critical paths. Here is my analysis:

**Batch 1 (lines 0–500):** Sub-sample mapper functions — potential integer overflow in `chunk_size = m_NaluLengthSize + nalu_length` (no upstream bound-check), but the encrypter context (not decrypter) limits direct impact for mp42aac.

**Batch 2 (lines 500–1000):** Encryption sample processing loops — `bytes_of_cleartext_data[i] + bytes_of_encrypted_data[i]` pointer advance with unvalidated sums.

**Batch 3 (lines 1000–1500):** Fragment encrypter and PrepareForSamples — no new heap issues.

**Batch 4 (lines 1500–2000):** Decrypter creation, `DecryptSampleData` — **line 1893**: bounds check `cleartext_size + encrypted_size` where AP4_UI16 + AP4_UI32 can overflow to 0, bypassing the check → ProcessBuffer called with 4GB size.

**Batch 5 (lines 2000–2500):** Decrypter chain, AP4_CencTrackDecrypter.

**Batch 6 (lines 2500–3000):** `AP4_CencSampleInfoTable::Create` (serialized variant) — **line 2932**: `sample_count * iv_size` overflow in the size check; **line 2935/2936**: constructor then allocates with the same overflowed value → heap under-alloc.

**Batch 7 (lines 3000–3500):** **Constructor line 3007**: `m_IvData.SetDataSize(m_IvSize * sample_count)` — `AP4_UI08 × AP4_UI32` multiplication overflows to 0 → 0-byte buffer; subsequent `SetIv()` writes 16 bytes → heap OOB write. `CreateSampleInfoTable` (line 3326–3330) passes `m_SampleInfoCount` directly read from file into this constructor.

---

## VULN: Integer Overflow in AP4_CencSampleInfoTable Constructor Leads to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleInfoTable::AP4_CencSampleInfoTable(), AP4_CencSampleEncryption::CreateSampleInfoTable()
- **行号**: 3007-3008, 3326-3330
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac/mp4decrypt → AP4_File parse → senc atom read → AP4_SencAtom constructor (stream.ReadUI32(m_SampleInfoCount), line 3191) → AP4_CencSampleInfoTable::Create (line 2746) → sample_encryption_atom->CreateSampleInfoTable() → new AP4_CencSampleInfoTable(..., m_SampleInfoCount, per_sample_iv_size) (line 3326-3330) → constructor line 3007: m_IvData.SetDataSize(m_IvSize * sample_count) → SetIv() OOB write
- **描述**: 在 `AP4_CencSampleInfoTable` 构造函数中，`m_IvSize`（`AP4_UI08`, 最大255）与 `sample_count`（`AP4_UI32`，来自 senc atom 中的 `sample_info_count` 字段，攻击者可控）相乘时均为无符号整数，结果仍存储于 `AP4_UI32` 中。当 `iv_size=16` 且 `sample_count=0x10000000` 时，`16 × 0x10000000 = 0x100000000`，截断为 0。`m_IvData.SetDataSize(0)` 只分配 0 字节的缓冲区，而后续 `CreateSampleInfoTable()` 循环中 `table->SetIv(i, data)` 按 `m_IvData.UseData() + m_IvSize × sample_index` 计算目标地址并写入 16 字节，因分配大小为 0 而造成堆越界写。
- **触发条件**: 构造含 `senc` box 的分片 MP4（`moof/traf/senc`），将其中 `sample_info_count` 字段设置为 `0x10000000`（或满足 `iv_size × count` 溢出的任意值），同时 box payload 中包含至少一条真实 IV 数据（16 字节）。将此文件传入调用 `AP4_CencDecryptingProcessor` 或 `AP4_CencSampleDecrypter::Create` 的工具（如 mp4decrypt）。
- **安全影响**: 堆缓冲区越界写入，攻击者可借此覆盖堆元数据或相邻对象，具备任意代码执行（RCE）潜力；最低后果为进程崩溃（DoS）。

## VULN: Integer Overflow in DecryptSampleData Bounds Check Bypasses Buffer Guard Leading to Heap OOB Read/Write
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSingleSampleDecrypter::DecryptSampleData()
- **行号**: 1893, 1908
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp4decrypt/library consumer → AP4_CencSampleDecrypter::DecryptSampleData() → m_SampleInfoTable->GetSampleInfo() (returns cleartext/encrypted sizes read from senc subsample entries via AddSubSampleData, line 3106-3108, directly from AP4_BytesToUInt16BE / AP4_BytesToUInt32BE on file bytes) → AP4_CencSingleSampleDecrypter::DecryptSampleData() → bounds check line 1893 → ProcessBuffer line 1908
- **描述**: `DecryptSampleData`（line 1885-1915）在处理子样本时，line 1893 执行边界校验：`if ((unsigned int)(in_end-in) < cleartext_size + encrypted_size)`，其中 `cleartext_size` 为 `AP4_UI16`（最大 65535），`encrypted_size` 为 `AP4_UI32`（来自 senc box，可达 `0xFFFFFFFF`）。C++ 中两者相加提升为 `unsigned int`（32位），当 `encrypted_size=0xFFFFFFFF` 且 `cleartext_size=1` 时，`1 + 0xFFFFFFFF = 0x100000000` 截断为 `0`，使得 `any_positive < 0` 恒为假，边界校验被绕过。随后 line 1908 调用 `m_Cipher->ProcessBuffer(in+cleartext_size, encrypted_size, out+cleartext_size, &encrypted_size)` 时，以 `encrypted_size=0xFFFFFFFF`（≈4GB）为读/写长度，而 `data_in`/`data_out` 缓冲区远小于此，造成堆越界读写。`cleartext_size` 和 `encrypted_size` 均直接来自文件中 senc atom 的 subsample 条目（`AddSubSampleData` line 3106-3108）。
- **触发条件**: 构造含 `senc` box 的分片 MP4，其中至少一个 subsample 条目的 `bytes_of_cleartext_data=1`（任意非零 uint16 值），`bytes_of_encrypted_data=0xFFFFFFFF`（uint32 最大值）。传入使用 `AP4_CencDecryptingProcessor` 进行解密的工具。
- **安全影响**: 堆越界读泄露内存布局信息；堆越界写可覆盖相邻堆块，具备任意代码执行（RCE）潜力；最低后果为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
