Now I have a complete picture. Let me consolidate the findings.

**Batch 1 (lines 1–188 of Ap4Piff.cpp):** The file is short; all the real logic delegates to `AP4_CencSampleEncryption(outer, size, stream)` in `Ap4CommonEncryption.cpp`.

**Batch 2 (CommonEncryption.cpp lines 3170–3195 — the stream-parsing constructor):**
At line 3193:
```cpp
AP4_Size payload_size = size - m_Outer.GetHeaderSize() - 4;
```
- `AP4_Size` = `AP4_UI32` (unsigned 32-bit)
- `m_Outer.GetHeaderSize()` for a full UUID atom = **28** (4+4+16+4)
- Minimum required subtraction: 28 + 4 = **32**
- Guard in `AP4_PiffSampleEncryptionAtom::Create()` is only `if (size < AP4_FULL_ATOM_HEADER_SIZE) return NULL` where `AP4_FULL_ATOM_HEADER_SIZE = 12`

So any atom with `12 <= size <= 31` passes the guard but causes `size - 32` to **wrap to ~4 GB** (e.g., `size=12 → payload_size = 0xFFFFFFE0`). This is passed to `m_SampleInfos.SetDataSize(0xFFFFFFE0)` → `new AP4_Byte[~4GB]` → `std::bad_alloc` → crash. Triggered during file open (`new AP4_File(*input)`), no `--key` needed.

**Batch 3 (CommonEncryption.cpp lines 3007–3008 — AP4_CencSampleInfoTable constructor):**
```cpp
m_IvData.SetDataSize(m_IvSize * sample_count);   // AP4_UI08 * AP4_UI32 in AP4_UI32
AP4_SetMemory(m_IvData.UseData(), 0, m_IvSize * sample_count);
```
- If `m_SampleInfoCount` (from file) = `0x20000000` and `iv_size = 8`: `8 × 0x20000000 = 0x100000000` → wraps to **0**
- `SetDataSize(0)` → `m_Buffer` stays NULL
- `CreateSampleInfoTable()` loops and calls `SetIv(0, data)` with `m_IvData.UseData() = NULL`
- `AP4_CopyMemory(NULL, iv, 8)` → NULL pointer dereference → crash
- Requires `--key` option to invoke decryption path

**AtomFactory confirmed** (Ap4AtomFactory.cpp line 517): `AP4_PiffSampleEncryptionAtom::Create((AP4_UI32)size_64, stream)` is called automatically for any UUID atom matching the PIFF sample encryption UUID during normal file parsing.

## VULN: Integer underflow in AP4_CencSampleEncryption constructor causes heap over-allocation and crash
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom&, AP4_Size, AP4_ByteStream&)
- **行号**: 3192-3195
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → new AP4_File(*input) → AP4_AtomFactory::CreateAtomFromStream() → AP4_PiffSampleEncryptionAtom::Create(size, stream) [Ap4AtomFactory.cpp:517] → new AP4_PiffSampleEncryptionAtom(size, version, flags, stream) [Ap4Piff.cpp:134] → AP4_CencSampleEncryption(*this, size, stream) [Ap4Piff.cpp:154] → AP4_CencSampleEncryption constructor [Ap4CommonEncryption.cpp:3193]
- **描述**: `AP4_Size` 是无符号 32 位整数，在构造函数中计算 `payload_size = size - m_Outer.GetHeaderSize() - 4`。对于 PIFF Sample Encryption（Full UUID）原子，`GetHeaderSize()` 返回 28（4 size + 4 type + 16 UUID + 4 version/flags），因此最小有效 atom size 为 32 字节。然而 `AP4_PiffSampleEncryptionAtom::Create()` 中的防护仅检查 `size < AP4_FULL_ATOM_HEADER_SIZE (= 12)`，当攻击者构造 size 在 [12, 31] 范围内的 atom 时，无符号减法 `size - 32` 发生整数下溢（如 size=12 时 payload_size = 0xFFFFFFE0 ≈ 4 GB）。随后 `m_SampleInfos.SetDataSize(0xFFFFFFE0)` 调用 `new AP4_Byte[4294967264]`，触发 `std::bad_alloc` 导致程序崩溃；若编译禁用异常，则 `stream.Read(NULL, 0xFFFFFFE0)` 引发 NULL 指针解引用崩溃。
- **触发条件**: 在 MP4 文件的 traf 容器中嵌入一个 UUID 类型为 PIFF Sample Encryption（UUID=A2394F525A9B4f14A2446C427C648DF4）、size 字段设为 12–31 的 atom；mp42aac 仅需打开该文件（无需 --key 参数）。
- **安全影响**: 进程因 std::bad_alloc 异常崩溃（DoS）；在禁用异常的构建中为 NULL 指针解引用崩溃。

## VULN: Integer overflow in AP4_CencSampleInfoTable constructor causes NULL pointer dereference via under-allocated IV buffer
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleInfoTable::AP4_CencSampleInfoTable(AP4_UI08, AP4_UI08, AP4_UI08, AP4_UI32, AP4_UI08)
- **行号**: 3007-3008 (构造函数) + 3074-3075 (SetIv 中的空指针写入)
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → DecryptAndWriteSamples() → AP4_CencSampleDecrypter::Create() → AP4_CencSampleInfoTable::Create() [Ap4CommonEncryption.cpp:2746] → sample_encryption_atom->CreateSampleInfoTable() [Ap4CommonEncryption.cpp:3326] → new AP4_CencSampleInfoTable(flags, 0, 0, m_SampleInfoCount, per_sample_iv_size) [Ap4CommonEncryption.cpp:3326] → constructor SetDataSize(m_IvSize * sample_count) [line 3007] → SetIv(0, data) → AP4_CopyMemory(NULL, iv, m_IvSize) [line 3075]
- **描述**: `AP4_CencSampleInfoTable` 构造函数在 `m_IvData.SetDataSize(m_IvSize * sample_count)` 处计算 IV 缓冲区大小。`m_IvSize`（`AP4_UI08`，典型值 8 或 16）与 `sample_count`（`AP4_UI32`，直接来自 MP4 文件中 `m_SampleInfoCount` 字段）相乘时均提升为 `AP4_UI32`，当乘积超过 `0xFFFFFFFF` 时静默截断为 0。例如 `iv_size=8, sample_count=0x20000000` → `8 × 0x20000000 = 0`。`SetDataSize(0)` 不分配任何内存，`m_IvData.m_Buffer` 保持为 NULL。随后 `CreateSampleInfoTable()` 循环中，只要流中还有 IV 数据（`data_size >= iv_size`），就调用 `SetIv(0, data)`；`SetIv` 计算 `dst = m_IvData.UseData() + 0 = NULL`，然后 `AP4_CopyMemory(NULL, iv, 8)` 触发 NULL 指针解引用崩溃。
- **触发条件**: 构造一个加密 MP4，使 PIFF/CENC Sample Encryption atom 的 `sample_info_count` 字段设为使 `iv_size × count` 溢出为 0 的值（如 0x20000000），同时 atom payload 中包含至少 iv_size 字节的 IV 数据（以通过 data_size 检查）；以任意 16 字节十六进制密钥运行 `mp42aac --key <any_32_hex_chars> crafted.mp4 out.aac`。
- **安全影响**: NULL 指针解引用导致进程崩溃（DoS）；在理论上可映射零地址的特殊环境中存在进一步利用的可能性。

<!-- AUDIT_PROMPT_VERSION: 1 -->
