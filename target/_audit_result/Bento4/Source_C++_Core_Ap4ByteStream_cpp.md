**Batch 1 (lines 1–368): ReadNullTerminatedString** — `size` is `unsigned int`; `size+1` overflows to 0 at UINT32_MAX; `SetDataSize(0)` leaves the existing allocation unchanged; `buffer.UseData()[0xFFFFFFFF]` writes 1 byte past the end of the current heap buffer. Real CWE-190 → CWE-122.

**Batch 2 (lines 369–600): CopyTo, SubStream**: CopyTo uses 64-bit `AP4_LargeSize` and clamps properly. SubStream ReadPartial/WritePartial clamps `m_Position+bytes_to_read` against `m_Size` in 64-bit arithmetic; Seek prevents `m_Position > m_Size`. No issues.

**Batch 3 (lines 600–900): DupStream, MemoryByteStream**: WritePartial line 762 `(AP4_Size)(m_Position+bytes_to_write)` truncates uint64→uint32. However `m_Position` in `AP4_MemoryByteStream` is constrained to ≤ GetDataSize() (uint32) by Seek(). Under accumulated sequential writes m_Position could reach 4GB as uint64 before the truncation triggers, but only via ≥4GB total writes — an output path, not MP4 parse input.

**Batch 4 (lines 900–987): BufferedInputStream::Seek**: The `to_skip = (AP4_Size)(position-m_SourcePosition)` cast is guarded by `position-m_SourcePosition <= m_SeekAsReadThreshold` (uint32 max 128KB). Safe.

---

## VULN: ReadNullTerminatedString Integer Overflow Leading to 1-Byte Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: AP4_ByteStream::ReadNullTerminatedString()
- **行号**: 353-368
- **CWE**: CWE-122 (Heap-based Buffer Overflow) via CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 4.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:N/I:L/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → (various box parsers) → AP4_ByteStream::ReadNullTerminatedString() on an unbounded or large-box-bounded stream
- **描述**: `size` 的类型是 `unsigned int`（32位无符号），从 0 开始在循环中递增。在循环体内，每次调用 `buffer.SetDataSize(size+1)` 为 buffer 分配空间，然后将读到的字节写入 `buffer.UseData()[size]`，再执行 `++size`。当 `size` 已为 `0xFFFFFFFF` 时，`size+1` 发生无符号整数溢出（wraps to 0），导致 `buffer.SetDataSize(0)` 被调用：此调用因 `0 <= m_BufferSize`（当前值为 0xFFFFFFFF）而不触发重分配，仅将 `m_DataSize` 置为 0，堆缓冲区指针 `m_Buffer` 仍指向原来分配的 0xFFFFFFFF 字节区域。随后执行 `buffer.UseData()[0xFFFFFFFF] = c`，该下标指向该 0xFFFFFFFF 字节分配的末尾之后第 1 个字节，造成 1 字节的堆缓冲区越界写入（off-by-one heap overflow）。
- **触发条件**: 攻击者需要构造一个 MP4 文件，使其中某个含有 null 终止字符串的 box（如 handler name、URL box 等）声明超过 4,294,967,295 字节的连续非零数据，且解析该字符串时所用的流未被更小的子流（AP4_SubStream）所限制。在 64 位系统上需要文件大小 ≥ 4GB。
- **安全影响**: 1 字节堆越界写入（值为攻击者控制的字节，写在 4GB 堆分配之后的紧邻字节），在最坏情况下可与堆布局技术结合用于有限程度的控制流劫持（RCE），更现实的情况是 DoS（heap corruption crash）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
