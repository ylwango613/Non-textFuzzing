## VULN: SENC OVERRIDE Flag Payload-Size Undercomputation → Out-of-Bounds Stream Read
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom& outer, AP4_Size size, AP4_ByteStream& stream)
- **行号**: 3181-3195
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.4 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: main() → new AP4_File(*input) → AP4_File::ParseStream() [moov_only=false，解析全部 top-level atom] → AP4_DefaultAtomFactory::CreateAtomFromStream() [moof→traf→senc] → AP4_SencAtom::Create(size, stream) → AP4_SencAtom(size, version, flags, stream) → AP4_CencSampleEncryption(*this, size, stream)
- **描述**: 当 senc atom 的 flags 设置了 AP4_CENC_SAMPLE_ENCRYPTION_FLAG_OVERRIDE_TRACK_ENCRYPTION_DEFAULTS（bit 0）时，构造函数在读取 m_SampleInfoCount 之前额外从流中消耗 20 字节（ReadUI24 algorithm_id + ReadUI08 per_sample_iv_size + Read(m_Kid, 16)）。但第 3193 行计算 payload_size = size − m_Outer.GetHeaderSize() − 4 = size − 16，没有减去这 20 个已消耗字节，导致 payload_size 比 senc box 内实际剩余字节多出 20。第 3195 行 stream.Read(m_SampleInfos.UseData(), payload_size) 因此从 senc box 边界之外再多读 20 字节，将紧随其后的下一个 atom 的前 20 字节写入 m_SampleInfos 缓冲区，并使文件流指针偏移到下一个 atom 内部 20 字节处，导致所有后续 atom 解析发生错误定位。
- **触发条件**: 构造含有 moof→traf→senc 的分片 MP4，senc atom 的 flags 字节设为 0x01（OVERRIDE flag），atom size ≥ 36（12 字节 Full Atom 头 + 20 字节 override 字段 + 4 字节 sample_count）。攻击者完全控制被越界读取的 20 字节内容（即跟在 senc 后面的任意 box 数据），可用于构造进一步利用链。
- **安全影响**: 来自相邻 atom 的原始字节被写入可由程序逻辑访问的 m_SampleInfos 缓冲区（信息泄漏）；后续所有 atom 在偏移 20 字节的错误位置被解析，可能级联触发 OOB 读/写或空指针解引用；在自动化 fuzzing 中可作为稳定崩溃路径。

## VULN: SENC Atom Minimum Size Check Too Loose → Integer Underflow in payload_size → Uncontrolled ~4 GB Allocation → Process Crash
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom& outer, AP4_Size size, AP4_ByteStream& stream)
- **行号**: 3193-3195
- **CWE**: CWE-191 (Integer Underflow (Wrap or Wraparound))
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: main() → new AP4_File(*input) → AP4_File::ParseStream() → AP4_DefaultAtomFactory::CreateAtomFromStream() [moof→traf→senc] → AP4_SencAtom::Create(size, stream) [Ap4SencAtom.cpp:48 仅检查 size < 12，size∈{12,13,14,15} 通过] → AP4_SencAtom(size, version, flags, stream) → AP4_CencSampleEncryption(*this, size, stream) → m_SampleInfos.SetDataSize(payload_size) → AP4_DataBuffer::ReallocateBuffer(0xFFFFFFFC) → new AP4_Byte[0xFFFFFFFC]
- **描述**: AP4_SencAtom::Create()（Ap4SencAtom.cpp:48）只检查 size < AP4_FULL_ATOM_HEADER_SIZE（即 12），size ∈ {12, 13, 14, 15} 均可通过检查进入构造函数。AP4_Size 为 uint32_t，第 3193 行计算 payload_size = size − m_Outer.GetHeaderSize() − 4 = size − 16；当 size < 16 时，无符号减法发生下溢（例如 12 − 16 = 0xFFFFFFFC ≈ 4 294 967 292）。随后第 3194 行 m_SampleInfos.SetDataSize(0xFFFFFFFC) 调用 AP4_DataBuffer::ReallocateBuffer(Ap4DataBuffer.cpp:210)，执行 new AP4_Byte[0xFFFFFFFC]，在绝大多数平台上抛出 std::bad_alloc，进程立即崩溃。
- **触发条件**: 在 MP4 的 moof→traf 路径内放置一个 senc box，将其 4 字节 size 字段设为 12、13、14 或 15（atom 的字节总长度即为该值）。
- **安全影响**: 进程崩溃（拒绝服务），可被任何能向目标投递一个 MP4 文件的攻击者稳定重现，无需任何权限或用户交互以外的条件，单文件即可触发。

<!-- AUDIT_PROMPT_VERSION: 1 -->
