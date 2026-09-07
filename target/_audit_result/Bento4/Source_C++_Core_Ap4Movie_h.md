Now I have all the information needed. Let me compile findings from my full analysis:

**Group 1 — CttsAtom (lines 77-85):** `entry_count` is read directly from the MP4 file with NO bounds check (unlike stco/stsc/stss which all have explicit checks). The allocation `new unsigned char[entry_count*8]` performs a 32-bit multiplication: when entry_count ≥ 0x20000000, `entry_count*8` overflows to 0, allocating a minimal buffer, while the subsequent loop iterates entry_count times accessing `buffer[i*8]` — massive heap OOB read.

**Group 2 — Stz2Atom (lines 88-120):** `table_size = (sample_count*m_FieldSize+7)/8` — both operands are 32-bit, causing overflow when sample_count=0x10000000 and field_size=16: product wraps to 0, table_size=0. Buffer `new unsigned char[0]` gets a minimal 1-byte allocation, stream reads 0 bytes (succeeds), then the switch-case 16 loop accesses `buffer[i*2]` for 268M iterations — all OOB from index i=1.

**Group 3 — StszAtom (line 78, minor):** Check uses `(size-8)/4` rather than the correct `(size-20)/4`, allowing m_SampleCount to be up to 3 entries larger than the atom payload, causing stream.Read to exceed atom bounds. Error-path-handled, limited impact.

**Group 4 — StcoAtom (lines 77-92):** Has a proper clamp check; `m_EntryCount*4` does not overflow 32-bit after clamping. Not vulnerable.

**Group 5 — StscAtom (lines 76-103):** Has a proper check using `(size-AP4_ATOM_HEADER_SIZE-4)/12`. Not vulnerable.

**Group 6 — StssAtom (lines 73-92):** Has a proper check. Not vulnerable.

**Attack path for both findings:** mp42aac → AP4_File → AP4_Movie(moov, stream) → AP4_Track(trak, stream) → AP4_AtomSampleTable(stbl, stream) → factory parses ctts/stz2 atom calling the vulnerable constructor.

## VULN: AP4_CttsAtom: Missing entry_count Bounds Check → Integer Overflow → Heap OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_CttsAtom::AP4_CttsAtom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 77-98
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_Movie::AP4_Movie(AP4_MoovAtom*, stream) → AP4_Track::AP4_Track(AP4_TrakAtom&, stream) → new AP4_AtomSampleTable(stbl, stream) → AP4_AtomFactory parses ctts atom → AP4_CttsAtom::AP4_CttsAtom(size, version, flags, stream)
- **描述**: `entry_count` 直接从 MP4 文件字段读取，**没有任何上界校验**（与 stco/stsc/stss 等原子均有 bounds check 不同）。第 80 行 `new unsigned char[entry_count*8]` 使用 32 位算术：当 `entry_count = 0x20000000` 时，`entry_count*8 = 0x100000000` 截断为 0，分配仅 1 字节的 minimal buffer；第 81 行 `stream.Read(buffer, 0)` 读取 0 字节成功返回；随后第 88-97 行循环执行 entry_count 次，`AP4_BytesToUInt32BE(&buffer[i*8])` 从 `i=1` 起即为堆越界读取，将相邻堆内存内容写入 m_Entries 数组。
- **触发条件**: 构造 MP4 文件，在 stbl 中放置一个 ctts 原子，将 atom size 设为合法最小值（如 24 字节），但 entry_count 字段设为 0x20000000；若目标系统有足够内存使 `m_Entries.SetItemCount(0x20000000)` 成功（约 4GB，64 位大内存服务器），则完整触发堆越界读；低内存系统下 SetItemCount 抛出 bad_alloc 造成 crash（DoS）。
- **安全影响**: 大内存系统上大规模堆越界读（每次 8 字节，最多 5.3 亿次），可能泄露堆上敏感内存内容（密钥、解析过的媒体元数据等）；所有系统上均可触发 std::bad_alloc 崩溃，造成 DoS。若 OOB 读越过 guard page 则触发 SIGSEGV。

## VULN: AP4_Stz2Atom: Integer Overflow in table_size → Heap OOB Read in Switch Loop
- **漏洞类别**: memory-safety
- **函数**: AP4_Stz2Atom::AP4_Stz2Atom(AP4_UI32, AP4_UI08, AP4_UI32, AP4_ByteStream&)
- **行号**: 88-121
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_Movie::AP4_Movie(AP4_MoovAtom*, stream) → AP4_Track::AP4_Track(AP4_TrakAtom&, stream) → new AP4_AtomSampleTable(stbl, stream) → AP4_AtomFactory parses stz2 atom → AP4_Stz2Atom::AP4_Stz2Atom(size, version, flags, stream)
- **描述**: 第 90 行 `unsigned int table_size = (sample_count*m_FieldSize+7)/8;`，其中 `sample_count`（AP4_UI32）与 `m_FieldSize`（AP4_UI08）的乘法在 32 位整数下运算。当 `m_FieldSize=16`、`sample_count=0x10000000` 时，`sample_count*m_FieldSize = 0x100000000` 溢出截断为 0，`table_size = 0`。第 91 行越界检查 `(0+8) > size` 对任何合法原子（size ≥ 12）均为 false，不触发提前返回。第 92 行分配 `new unsigned char[0]`（最小合法分配，仅 0-1 字节），第 93 行 `stream.Read(buffer, 0)` 成功读取 0 字节。随后第 116-119 行的 case 16 循环执行 sample_count 次，从 `buffer[i*2]` 读取 2 字节：从 `i=1` 起（即 buffer[2]）即已越界，造成大规模堆越界读。
- **触发条件**: 构造 MP4 文件，在 stbl 中放置 stz2 原子，设置 field_size=16、sample_count=0x10000000（268,435,456），原子 payload 为空（size=20 字节）。系统需有约 1GB 可用内存使 `m_Entries.SetItemCount(0x10000000)` 成功（AP4_UI32 数组，4 字节/项 × 0x10000000 = 1GB）。条件较 CttsAtom 更易满足（仅需 1GB vs 4GB）。
- **安全影响**: 成功后执行约 2.68 亿次堆越界读（每次 2 字节），将相邻堆内存内容填入 m_Entries 数组；可读取进程堆上的任意内存内容（潜在信息泄露），也可因越过 guard page 而 SIGSEGV（DoS）；若越界读扫过 free chunk header 等结构体可为进一步利用（如 heap grooming 辅助 RCE）提供信息。低内存系统下 SetItemCount OOM 崩溃即为 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
