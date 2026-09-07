Now I have all the information needed. Let me compile the findings from my systematic read through all batches.

**Batch summary:**
- `Ap4Piff.h`: 128-line header declaring `AP4_PiffSampleEncryptionAtom` and `AP4_PiffTrackEncryptionAtom`
- `Ap4Piff.cpp`: Parsing delegates entirely to `AP4_CencSampleEncryption(outer, size, stream)` and `AP4_CencTrackEncryption`
- `Ap4CommonEncryption.cpp` lines 3167-3196: Constructor reads `m_SampleInfoCount` from stream, then computes `payload_size = size - m_Outer.GetHeaderSize() - 4` — an `AP4_Size` (unsigned 32-bit) subtraction
- `Ap4CommonEncryption.cpp` lines 2996-3008: `AP4_CencSampleInfoTable` constructor computes `m_IvSize * sample_count` (both from file data) to allocate `m_IvData`
- `Ap4AtomFactory.cpp:517`: Factory parses PIFF Sample Encryption atom unconditionally on any MP4 file opening (no MINI_BUILD guard on parsing)
- `Ap4DataBuffer.cpp`: `SetDataSize` return values unchecked by callers; `UseData()` returns raw `m_Buffer` which remains NULL on zero-size allocation

Two confirmed memory-safety bugs follow.

## VULN: Integer Underflow in AP4_CencSampleEncryption Constructor → OOM Crash / Potential NULL Deref
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom&, AP4_Size, AP4_ByteStream&)
- **行号**: 3193-3195
- **CWE**: CWE-191 (Integer Underflow / Wrap-around)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4 output.aac` → `AP4_File(stream)` → atom factory parses any `uuid` atom → `AP4_AtomFactory.cpp:517` calls `AP4_PiffSampleEncryptionAtom::Create((AP4_UI32)size_64, stream)` → `Create` checks only `if (size < AP4_FULL_ATOM_HEADER_SIZE /*=12*/)` → proceeds for size 12–31 → `new AP4_PiffSampleEncryptionAtom(size, version, flags, stream)` → `AP4_CencSampleEncryption(*this, size, stream)` → `AP4_Size payload_size = size - m_Outer.GetHeaderSize() /*=28*/ - 4` underflows → `m_SampleInfos.SetDataSize(~0xFFFFFFEC)` → `ReallocateBuffer(0xFFFFFFEC)` → `new AP4_Byte[0xFFFFFFEC]` → `std::bad_alloc`
- **描述**: `AP4_Size`（`uint32_t`，无符号）减法 `size - 28 - 4`：`Create()` 只检查 `size < AP4_FULL_ATOM_HEADER_SIZE (12)`，而 PIFF UUID 全头实际需要至少 32 字节（`AP4_FULL_UUID_ATOM_HEADER_SIZE=28` + 4 字节 sample_count 字段）。当攻击者令 atom 声明 size 在 12–31 范围内时，减法结果绕回（例如 size=12 → `12−32 = 0xFFFFFFEC`），随后以此巨量值调用 `m_SampleInfos.SetDataSize()`，触发 ~4GB 分配，抛出 `std::bad_alloc` 导致进程崩溃（DoS）；若使用不抛异常的自定义分配器则 `m_Buffer` 保持 NULL，后续 `stream.Read(NULL, huge)` 引发 NULL 指针解引用。
- **触发条件**: 在 MP4 文件的 `traf` 或顶层容器中放置一个 `uuid` atom（`AP4_UUID_PIFF_SAMPLE_ENCRYPTION_ATOM`），其 box size 字段设为 12–31 之间任意值（例如 12）。
- **安全影响**: 进程因 `std::bad_alloc` 或 NULL 指针解引用立即崩溃（确定性 DoS）；在使用自定义分配器的嵌入式或服务器环境中，返回 NULL 后写入 NULL 地址可能进一步升级为任意代码执行。

## VULN: Integer Overflow in AP4_CencSampleInfoTable Constructor → NULL Pointer Dereference Write
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleInfoTable::AP4_CencSampleInfoTable(AP4_UI08, AP4_UI08, AP4_UI08, AP4_UI32, AP4_UI08)
- **行号**: 3007-3008
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac --key <hex> input.mp4 output.aac` → 文件解析创建 `AP4_PiffSampleEncryptionAtom`（从流读入 `m_SampleInfoCount=0x10000000`）→ 解密路径 `AP4_CencSampleDecrypter::Create` → `AP4_CencSampleInfoTable::Create(sample_description, traf, ...)` → `sample_encryption_atom->CreateSampleInfoTable(...)` → `new AP4_CencSampleInfoTable(flags, ..., m_SampleInfoCount=0x10000000, per_sample_iv_size=16)` → 构造函数 `m_IvData.SetDataSize(16 * 0x10000000)` 溢出为 0 → `m_Buffer` 保持 NULL → `CreateSampleInfoTable` 循环第一次调用 `table->SetIv(0, data)` → `dst = NULL + 0 = NULL` → `AP4_CopyMemory(NULL, data, 16)` 即 `memcpy(NULL, …, 16)` → SIGSEGV
- **描述**: `AP4_UI08 m_IvSize`（iv_size，最大 16）与 `AP4_UI32 sample_count`（直接来自 senc/PIFF atom 的 4 字节字段）相乘结果隐式截断为 `uint32_t`：当 `sample_count = 0x10000000`、`iv_size = 16` 时，乘积 `0x100000000` 绕回为 0。`SetDataSize(0)` 不触发 `ReallocateBuffer`，`m_Buffer` 维持 NULL。随后在 `CreateSampleInfoTable` 的样本循环中，`SetIv(0, data)` 内执行 `memcpy(NULL, data, 16)`，造成 NULL 指针写入（SIGSEGV）。`payload_size = size - 32` 可以很小（如 18 字节），使第一次迭代的 `data_size < per_sample_iv_size` 检查不会提前 `goto end`，确保能到达崩溃点。
- **触发条件**: 构造一个带 PIFF/senc 加密的分片 MP4 文件：在 sample encryption atom 中将 `sample_count`（`SampleInfoCount` 字段）设为 `0x10000000`（4 字节，小端），`per_sample_iv_size = 16`（由 tenc 或 PIFF Track Encryption atom 控制）；atom 本身可以非常小（size ≈ 50 字节），无需真实样本数据。需以 `--key` 参数运行 `mp42aac` 以触发解密路径，或可通过其他调用 `CreateSampleInfoTable` 的 Bento4 工具/API 触发。
- **安全影响**: 确定性进程崩溃（DoS）；在 NULL 地址可映射的平台（部分 32 位嵌入式系统）或结合信息泄露控制写入内容时，可能升级为任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
