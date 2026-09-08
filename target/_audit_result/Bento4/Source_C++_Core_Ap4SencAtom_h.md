I now have complete analysis. Let me write the final vulnerability report.

## VULN: Integer Underflow → Heap Overflow in AP4_CencSampleEncryption Stream Constructor
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom& outer, AP4_Size size, AP4_ByteStream& stream)
- **行号**: 3193-3195 (Ap4CommonEncryption.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4` → `AP4_File(stream)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_SencAtom::Create(size_32=12, stream)` → `new AP4_SencAtom(12, version, flags, stream)` → `AP4_CencSampleEncryption(outer, size=12, stream)`（构造函数）→ `payload_size = 12 - GetHeaderSize(12) - 4 = 0xFFFFFFFC` → `m_SampleInfos.SetDataSize(0xFFFFFFFC)` → `new AP4_Byte[0xFFFFFFFC]`
- **描述**: 在 `AP4_CencSampleEncryption` 的流读取构造函数中，`payload_size` 通过无符号减法计算：`AP4_Size payload_size = size - m_Outer.GetHeaderSize() - 4`。`AP4_FULL_ATOM_HEADER_SIZE = 12`，函数入口的唯一校验是 `if (size < 12) return NULL`（见 `AP4_SencAtom::Create`，行48）。当 `size` 为 12–15 时，满足 `>= 12` 的检查，但 `size - 12 - 4` 产生 32 位无符号下溢，结果为 `0xFFFFFFFC`–`0xFFFFFFFF`（约 4GB）。随后 `m_SampleInfos.SetDataSize(payload_size)` 在 `ReallocateBuffer` 中调用 `new AP4_Byte[4GB]`；该返回值未被检查，若分配失败将抛出未捕获的 `std::bad_alloc` 导致进程崩溃；若在 32 位地址空间中分配器返回一个极小的缓冲区，后续的 `stream.Read(m_SampleInfos.UseData(), 0xFFFFFFFC)` 将读取 4GB 数据写入该小缓冲区，造成堆缓冲区溢出。`AP4_SencAtom` 已在原子工厂中注册（`AP4_AtomFactory.cpp:657-659`），任何包含 `senc` box 的 MP4 文件均触发此路径。
- **触发条件**: 构造一个 `senc` box，box_size 字段（big-endian 4 字节）设置为 12、13、14 或 15，box_type 为 `senc`（0x73656E63），后跟 4 字节 version+flags。整个文件其余部分合法。该 box 可置于 `moov/trak/mdia/minf/stbl` 或 `moof/traf` 容器中。
- **安全影响**: 最坏情况下：堆缓冲区溢出，攻击者可通过精心布置的堆布局实现任意代码执行（RCE）；最常见情况：`std::bad_alloc` 导致程序崩溃（DoS）。

## VULN: Integer Overflow → Null Pointer Dereference in AP4_CencSampleInfoTable Constructor
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleInfoTable::AP4_CencSampleInfoTable(AP4_UI08 flags, AP4_UI08 crypt_byte_block, AP4_UI08 skip_byte_block, AP4_UI32 sample_count, AP4_UI08 iv_size)
- **行号**: 3007-3008 (Ap4CommonEncryption.cpp)
- **CWE**: CWE-190 (Integer Overflow) → CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac --key <key> input.mp4` → `DecryptAndWriteSamples` → `AP4_SampleDecrypter::Create(pdesc, key, 16)` → (CENC路径) `AP4_CencSampleDecrypter::Create` → `AP4_CencSampleInfoTable::Create` → `AP4_CencSampleEncryption::CreateSampleInfoTable` → `new AP4_CencSampleInfoTable(flags, ..., m_SampleInfoCount=0x10000000, per_sample_iv_size=16)` → 构造函数中 `m_IvSize(16) * sample_count(0x10000000) = 0`（32位溢出）→ `m_IvData.SetDataSize(0)` → 缓冲区指针为 NULL → `CreateSampleInfoTable` 循环 `table->SetIv(0, data)` → `AP4_CopyMemory(NULL, iv, 16)` → 空指针解引用
- **描述**: `AP4_CencSampleInfoTable` 构造函数第 3007 行对 `m_IvSize`（`AP4_UI08`，最大 255）和 `sample_count`（`AP4_UI32`，来自文件字段 `m_SampleInfoCount`）执行乘法：`m_IvData.SetDataSize(m_IvSize * sample_count)`。在 C++ 中，`AP4_UI08` 提升为 `AP4_UI32` 后相乘，结果仍为 32 位，当乘积超过 `2^32` 时产生整数溢出。例如 `iv_size=16, sample_count=0x10000000`（`2^28`）时乘积为 `16 * 2^28 = 2^32 ≡ 0`。`SetDataSize(0)` 不分配内存，内部缓冲区指针保持为 NULL（`m_Buffer = NULL`）。第 3008 行 `AP4_SetMemory(m_IvData.UseData(), 0, 0)` 为 `memset(NULL, 0, 0)`（UB，通常无操作）。随后在 `CreateSampleInfoTable` 循环中调用 `table->SetIv(0, data)`，其内部执行 `AP4_CopyMemory(m_IvData.UseData() + 0, iv, 16)`，即 `memcpy(NULL, iv, 16)`，导致空指针写入（段错误，进程崩溃）。返回值 `SetDataSize` 在构造函数中未被检查。
- **触发条件**: 构造包含加密音频轨道的 MP4 文件（`enca` sample description，`sinf` 中指定 CENC/PIFF 加密方案，`tenc` 中 `per_sample_iv_size=16`），`senc` atom 的 `sample_info_count` 字段设置为 `0x10000000`（268435456），并在 payload 中附加至少 16 字节合法 IV 数据。以 `mp42aac --key <任意16字节hex> input.mp4 out.aac` 执行即可触发。
- **安全影响**: 空指针写（memcpy to NULL）导致进程崩溃（DoS）。在部分 OS/内存管理配置下，若 NULL 页面可映射，可能升级为任意写（有限 RCE 可能）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
