Now I have all the context needed. Let me synthesize the findings across the two files.

**Group 1 findings (Ap4CommonEncryption.cpp lines 3170-3196 — stream constructor):**
- `payload_size = size - m_Outer.GetHeaderSize() - 4` with `AP4_Size` (uint32_t); if atom `size` ∈ [12, 15] (minimum allowed by the `< AP4_FULL_ATOM_HEADER_SIZE` check = 12) the subtraction wraps to ~0xFFFFFFFC
- `m_SampleInfos.SetDataSize(0xFFFFFFFC)` → `new AP4_Byte[0xFFFFFFFC]` → `std::bad_alloc` / crash

**Group 2 findings (Ap4CommonEncryption.cpp lines 3007-3008, SetIv 3074):**
- Constructor: `m_IvData.SetDataSize(m_IvSize * sample_count)` — both `AP4_UI08` × `AP4_UI32` in 32-bit arithmetic; for iv_size=16, sample_count=0x10000001: product = 0x10 = 16 (overflow), allocates only 16 bytes
- `SetIv(1, data)`: check `1 >= 0x10000001` fails → writes 16 bytes at `m_IvData+16` → heap OOB write

**Group 3 findings (lines 3181-3195):**
- OVERRIDE flag path reads 20 extra bytes (algorithm_id/iv_size/kid) that are NOT deducted from `payload_size`; `stream.Read()` reads 20 bytes past the atom boundary into the next atom's data

## VULN: Integer Underflow in senc payload_size → OOM Crash (DoS)
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom&, AP4_Size, AP4_ByteStream&)
- **行号**: 3193-3195
- **CWE**: CWE-191 (Integer Underflow)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File() → atom factory → AP4_SencAtom::Create() → new AP4_SencAtom(size, version, flags, stream) → AP4_CencSampleEncryption(outer, size, stream)
- **描述**: `AP4_Size payload_size = size - m_Outer.GetHeaderSize() - 4` 中 `AP4_Size` 为无符号 32 位；`AP4_FULL_ATOM_HEADER_SIZE = 12`，而 Create() 仅检查 `size < 12`，允许 size ∈ {12,13,14,15} 通过。当 size=12 时，`payload_size = 12 - 12 - 4`（无符号下溢）= 0xFFFFFFFC ≈ 4 GB。随后 `m_SampleInfos.SetDataSize(0xFFFFFFFC)` 触发 `new AP4_Byte[0xFFFFFFFC]`，抛出 `std::bad_alloc` 或因平台 overcommit 后首次 page-fault 崩溃，进程立即终止。
- **触发条件**: 构造一个 senc atom，将 box-size 字段设置为 12、13、14 或 15（仅需合法的 4-byte size + 4-byte type + 4-byte version/flags），放置在 MP4 文件的 traf 容器中。
- **安全影响**: 确定性崩溃（DoS），进程终止；不需要用户交互（仅传入 MP4 文件）。

## VULN: Integer Overflow in IV Buffer Allocation → Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleInfoTable::AP4_CencSampleInfoTable / AP4_CencSampleInfoTable::SetIv
- **行号**: 3007-3008 / 3074-3075
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File 解析 traf → AP4_SencAtom::Create() 存储 m_SampleInfoCount（来自文件） → AP4_CencSampleInfoTable::Create() → new AP4_CencSampleInfoTable(flags, crypt, skip, m_SampleInfoCount, iv_size) → SetIv(i, data)
- **描述**: 构造函数第 3007 行 `m_IvData.SetDataSize(m_IvSize * sample_count)` 中，`m_IvSize`（AP4_UI08，最大 255）× `sample_count`（AP4_UI32，来自文件）在 32 位无符号算术中溢出：iv_size=16 且 sample_count=0x10000001 时积为 0x100000010 & 0xFFFFFFFF = 0x10 = 16，仅分配 16 字节。而 `m_SampleCount` 仍为 0x10000001。随后在 `SetIv()` 第 3073 行 `sample_index >= m_SampleCount` 的边界检查对 sample_index=1 通过（1 < 0x10000001），第 3074 行 `dst = m_IvData.UseData() + m_IvSize * 1 = base + 16`，第 3075 行 `AP4_CopyMemory(dst, iv, 16)` 向 16 字节堆块末尾之后写入 16 字节攻击者可控数据（来自 senc 的 IV 负载），造成堆缓冲区溢出。
- **触发条件**: 构造 MP4 文件，使 tenc atom 中 per_sample_iv_size = 16；senc atom 中 sample_info_count 字段 = 0x10000001，payload 包含至少 32 字节 IV 数据（atom size ≥ 48）。
- **安全影响**: 堆越界写 16 字节攻击者可控数据至相邻堆对象，最坏情况下可利用堆布局实现远程代码执行（RCE）；至少导致崩溃（DoS）。

## VULN: senc OVERRIDE Flag OOB Stream Read Past Atom Boundary
- **漏洞类别**: memory-safety
- **函数**: AP4_CencSampleEncryption::AP4_CencSampleEncryption(AP4_Atom&, AP4_Size, AP4_ByteStream&)
- **行号**: 3181-3195
- **CWE**: CWE-131 (Incorrect Calculation of Buffer Size) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File 解析 traf → AP4_SencAtom::Create()（flags 含 OVERRIDE_TRACK_ENCRYPTION_DEFAULTS 位）→ AP4_CencSampleEncryption(outer, size, stream) → 第 3181-3188 行消耗 20 字节 → 第 3193 行 payload_size 计算未扣除 20 字节
- **描述**: 当 senc atom 的 flags 字段第 0 位（AP4_CENC_SAMPLE_ENCRYPTION_FLAG_OVERRIDE_TRACK_ENCRYPTION_DEFAULTS）被置位时，构造函数先从 stream 读取 AlgorithmId（3 B）、PerSampleIvSize（1 B）、KID（16 B）共 20 字节，再读 sample_info_count（4 B），但随后 `payload_size = size - m_Outer.GetHeaderSize() - 4` 的计算未减去这 20 字节。导致 `stream.Read(m_SampleInfos.UseData(), payload_size)` 多读 20 字节，越出当前 senc atom 边界，把相邻 atom 的数据纳入 m_SampleInfos，后续以 IV/subsample 数据解析邻接 atom 字节，造成越界读取及信息泄露。
- **触发条件**: 构造一个 senc atom，flags = 0x000001（OVERRIDE），size 任意 ≥ 36（保证 OVERRIDE 字段完整），后跟另一 atom 含有效字节。
- **安全影响**: 读取相邻 atom（如 mdat 或 moov 子结构）的最多 20 字节，信息泄露；若邻接数据被解析为 subsample_count 并驱动后续访问，可能引发进一步越界读或解析混乱。

<!-- AUDIT_PROMPT_VERSION: 1 -->
