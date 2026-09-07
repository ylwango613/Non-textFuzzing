Now I have enough context. Let me finalize my analysis of all paths through the OMA DCF code reachable from mp42aac.

**Batch 1 group analysis (Ap4OmaDcf.cpp:436-509, CTR decrypter):**
- `DecryptSampleData` CTR: `header_size` check is present (line 459), protects underflow in `payload_size`.
- `GetDecryptedSampleSize` CTR (lines 507–508): `sample.GetSize()-crypto_header_size` with no pre-check — unsigned subtraction wraps if `sample.GetSize() < crypto_header_size`. Returned huge value goes into `SetSampleSize` in the pre-pass processor. NOT in the direct `mp42aac::DecryptAndWriteSamples()` call chain, only reachable via `AP4_OmaDcfTrackDecrypter` / `AP4_Processor::Process`.

**Batch 2 group analysis (Ap4OmaDcf.cpp:530-628, CBC decrypter):**
- `DecryptSampleData` CBC (lines 554–568): `header_size = (selective?1:0) + 16`. Guard only checks `header_size > in_size`. If `in_size = header_size + k` where `1 ≤ k ≤ 15`, `payload_size = k`. After `Reserve(k)` allocates 1024 bytes and `out = UseData()`, `m_Cipher->ProcessBuffer(in, k, out, &out_size, true)` is called.

In `AP4_CbcStreamCipher::DecryptBuffer` with `in_size = k (1–15)`:
- `blocks_needed = (0+k)/16 = 0` → `*out_size = 0`
- `in_size != 0` → shortcut not taken
- No blocks decrypted → `out` pointer NOT advanced
- `if (is_last_buffer)`: `*(out-1)` executed — reads **1 byte before the `data_out` allocation** (heap OOB read)

This is confirmed CWE-125 triggered from a crafted MP4 with CBC OMA DCF, reachable from `mp42aac` via `DecryptAndWriteSamples` → `AP4_SampleDecrypter::Create(TYPE_OMA)` → `AP4_OmaDcfCbcSampleDecrypter::DecryptSampleData`.

**Batch 3 group analysis (Ap4OhdrAtom.cpp parsing):**
- `content_id_length`, `rights_issuer_url_length`, `textual_headers_length` read as AP4_UI16 (max 65535) — no check against atom boundary before allocations and stream reads. Reads past atom boundary → stream confusion/parse-state corruption. Not a heap overflow (buffers sized exactly to declared length).

**Batch 4 group analysis (Ap4OmaDcf.cpp:155–218, GrpiAtom group key decryption):**
- `key_buffer_size = GetGroupKey().GetDataSize()` (AP4_UI16, max 65535). Allocation and cipher output are both bounded by 65535. No overflow.

## VULN: Heap OOB Read in OmaDcf CBC Sample Decryption Non-Block-Aligned Payload
- **漏洞类别**: memory-safety
- **函数**: AP4_OmaDcfCbcSampleDecrypter::DecryptSampleData()
- **行号**: 554-568 (Ap4OmaDcf.cpp), OOB read 实发于 Ap4StreamCipher.cpp AP4_CbcStreamCipher::DecryptBuffer is_last_buffer 分支
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → DecryptAndWriteSamples() → AP4_SampleDecrypter::Create(AP4_PROTECTION_SCHEME_TYPE_OMA) → AP4_OmaDcfSampleDecrypter::Create() → new AP4_OmaDcfCbcSampleDecrypter() → decrypter->DecryptSampleData(encrypted_data, decrypted_data) → m_Cipher->ProcessBuffer(in, payload_size, out, &out_size, true) → AP4_CbcStreamCipher::DecryptBuffer(in=1~15字节, in_size=1~15, out=heap_buf_start, out_size=&0, is_last_buffer=true) → `*(out-1)` 在 is_last_buffer 分支读取 out 指针前一字节
- **描述**: `DecryptSampleData` (CBC) 计算 `payload_size = in_size - header_size` 后调用 `m_Cipher->ProcessBuffer(in, payload_size, out, &out_size, true)`，但未校验 `payload_size >= AP4_CIPHER_BLOCK_SIZE(16)`。当 `payload_size` 为 1–15 时，`AP4_CbcStreamCipher::DecryptBuffer` 内 `blocks_needed=0`（无整块被解密），`out` 指针未被推进，但 `is_last_buffer=true` 分支直接执行 `AP4_UI08 pad_byte = *(out-1)`，读取 `data_out` 堆缓冲区起始地址前 1 字节（glibc chunk 元数据区域），构成 1 字节堆越界读。
- **触发条件**: 构造 OMA DCF CBC 加密的 MP4 文件，`odaf` 原子中 `encryption_method=AES_CBC`，音频 sample 总字节数等于 `header_size + k`（1 ≤ k ≤ 15），其中 `header_size = (selective_encryption?1:0) + 16`（例如，`selective_encryption=false`，sample 大小 17 字节：16 字节 IV + 1 字节密文）。
- **安全影响**: 读取堆 chunk 元数据 1 字节（信息泄露），通常触发 `AP4_ERROR_INVALID_FORMAT` 返回导致 mp42aac 输出"ERROR: failed to decrypt sample"并终止（DoS）；在内存 sanitizer 环境下会被捕获，在特定堆布局下存在极低概率 crash 风险。

## VULN: Integer Underflow in OmaDcf CTR GetDecryptedSampleSize Returns Wrap-Around Size
- **漏洞类别**: memory-safety
- **函数**: AP4_OmaDcfCtrSampleDecrypter::GetDecryptedSampleSize()
- **行号**: 507-508 (Ap4OmaDcf.cpp)
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: AP4_OmaDcfDecryptingProcessor::Initialize() → AP4_StandardDecryptingProcessor / AP4_Processor::Process() → AP4_OmaDcfTrackDecrypter::GetProcessedSampleSize(sample) → m_Cipher->GetDecryptedSampleSize(sample) → `return sample.GetSize()-crypto_header_size`（无符号下溢）→ 回传 UINT32_MAX-k → locator.m_SampleTable->SetSampleSize(index, UINT32_MAX-k) 及 `current_chunk_size += UINT32_MAX-k`（AP4_Size uint32 环绕溢出）
- **描述**: `GetDecryptedSampleSize()` 第 507-508 行 `return sample.GetSize()-crypto_header_size;` 在 `sample.GetSize() < crypto_header_size` 时发生 AP4_Size（uint32）无符号减法下溢，返回值约为 UINT32_MAX。该值被传入 `SetSampleSize()` 写入输出文件的 `stsz` 原子，同时与 `current_chunk_size`（AP4_Size uint32）相加发生环绕溢出，导致 chunk offset 计算完全错误，输出 MP4 文件元数据严重损坏。
- **触发条件**: 构造 OMA DCF CTR 加密的 MP4 文件，`odaf` 原子中 `selective_encryption=true`（header_size=1+iv_length=17），音频 sample 大小 < 17 字节（例如 1 字节），使 `sample.GetSize()-crypto_header_size` 发生无符号下溢；需使用 `AP4_OmaDcfDecryptingProcessor` 批量处理路径（而非 mp42aac 直接的 per-sample 解密路径）。
- **安全影响**: 输出 MP4 文件 stsz 原子中 sample size 字段被写入 UINT32_MAX 级别的畸形值，后续播放器尝试分配 ~4GB 缓冲区（OOM/DoS）；chunk offset 链全部错误（输出文件不可播放）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
