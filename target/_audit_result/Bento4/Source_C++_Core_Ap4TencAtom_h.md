Based on my thorough analysis, I have enough information to write the final report.

## VULN: AP4_CencSampleEncryption Senc-Atom Payload-Size Integer Underflow → Crash (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom&, AP4_Size, AP4_ByteStream&)
- **行号**: 3193-3195 (Ap4CommonEncryption.cpp)
- **CWE**: CWE-191 (Integer Underflow / Wrap-around)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → new AP4_File(*input) → AP4_File::ParseStream() → AP4_AtomFactory::CreateAtomFromStream(moof container) → CreateAtomFromStream(traf container) → CreateAtomFromStream(senc, size_32=12) → AP4_SencAtom::Create(12, stream) → new AP4_SencAtom(12, version, flags, stream) → AP4_CencSampleEncryption(*this, 12, stream) → payload_size = 12 - GetHeaderSize(12) - 4 = 0xFFFFFFFC → m_SampleInfos.SetDataSize(0xFFFFFFFC) → ReallocateBuffer(0xFFFFFFFC) → new AP4_Byte[4294967292] → std::bad_alloc → 进程崩溃
- **描述**: 在 `AP4_CencSampleEncryption` 的流式解析构造函数中，`payload_size` 的计算方式为 `size - m_Outer.GetHeaderSize() - 4`，三个操作数均为无符号 32 位整数。`AP4_SencAtom::Create` 只检查 `size < AP4_FULL_ATOM_HEADER_SIZE (12)` 就放行，而 senc 全量原子头部（12 字节）加 SampleInfoCount（4 字节）共需至少 16 字节；当攻击者将 senc box 的 size 字段设为 12、13、14 或 15 时，`12 - 12 - 4`（以 `AP4_UI32` 计算）下溢为 `0xFFFFFFFC`，导致随后 `ReallocateBuffer(0xFFFFFFFC)` 对 `new AP4_Byte[4294967292]` 发起约 4 GB 的堆分配，触发 `std::bad_alloc` 异常崩溃程序。此路径在 mp42aac 打开文件时的原子解析阶段（`new AP4_File(*input)`）即可触发，无需 `--key` 选项。
- **触发条件**: 在 MP4 文件的 moof/traf 子树中构造一个声明 size=12（或 13/14/15）的 senc 全量原子。工厂只验证 `size >= 8 && size <= bytes_available`，均能通过，随即将 size_32=12 传入 `AP4_SencAtom::Create`，绕过唯一的 `size < 12` 校验，进入有缺陷的构造函数。
- **安全影响**: 无条件进程崩溃（DoS）；在低内存系统上通过 `bad_alloc` 终止，在高内存系统上分配成功后随即发生超大流读取并最终崩溃；对处理不可信 MP4 文件的服务（批量转码、媒体服务器）构成持续性拒绝服务威胁。

<!-- AUDIT_PROMPT_VERSION: 1 -->
