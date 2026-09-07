Now I have enough context for a complete analysis. Let me summarize the findings before the final output.

**Group 1 analysis (Ap4EsDescriptor.cpp lines 61–111):**

- `payload_size` is `AP4_UI32` from the MP4 file via base-128 decoding in `DescriptorFactory`.
- `start` and `offset` are `AP4_Position` (64-bit unsigned).
- Lines 100–103: `payload_size - AP4_Size(offset-start)` — if the consumed bytes exceed `payload_size` (e.g., `payload_size=3` with `STREAM_DEPENDENCY` flag causing 5 bytes read), the subtraction wraps to ≈`0xFFFFFFFE`, creating an AP4_SubStream with a ~4 GB declared size.
- With `m_Size ≈ 0xFFFFFFFE`, the `ReadPartial` clamp never fires, and the sub-descriptor factory loop reads data from the real underlying stream **well beyond the intended ES descriptor payload**, into whatever follows in the file.
- This is CWE-191 (integer underflow) → CWE-125 (OOB read): data outside the ES descriptor's payload region is read into heap-allocated descriptor objects.
- `AP4_UnknownDescriptor` (and similar) in this path allocates heap buffers whose size comes from base-128 decoding of attacker-placed bytes in the adjacent file region, giving the attacker further control over heap allocation sizes.

**Group 2 analysis (lines 93–97 — wrong flag check):**

- The second `if (m_Flags & AP4_ES_DESCRIPTOR_FLAG_URL)` should be `AP4_ES_DESCRIPTOR_FLAG_OCR_STREAM`. This is a logic bug: when only OCR_STREAM is set (no URL), OCR_ES_Id is NOT read, silently shifting stream position. This indirectly worsens the underflow by making `offset-start` predictably smaller, but is itself a logic/parsing error, not independently a memory-safety bug.

## VULN: Integer Underflow in AP4_EsDescriptor Sub-descriptor SubStream Size
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)
- **行号**: 100-103
- **CWE**: CWE-191 (Integer Underflow leading to Out-of-Bounds Read, CWE-125)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory → AP4_EsdsAtom → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_EsDescriptor::AP4_EsDescriptor(stream, header_size, payload_size) → line 100-103
- **描述**: 在 `AP4_EsDescriptor` 的流构造函数中，局部变量 `payload_size`（AP4_UI32，来自文件中 base-128 编码的描述符长度字段）减去已消耗字节数 `AP4_Size(offset-start)` 时，若 flags 字节中设置了 `AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY`（bit0）或 `AP4_ES_DESCRIPTOR_FLAG_URL`（bit1），则消耗的字节数可超过 `payload_size` 指定的大小，导致无符号减法下溢，结果约为 `0xFFFFFFFE`（~4 GB）。该值被传递给 `AP4_SubStream` 的第三个参数（`AP4_LargeSize size`），使 SubStream 声称持有约 4 GB 数据。随后 `AP4_DescriptorFactory` 在此 SubStream 上循环解析子描述符：`ReadPartial` 内的 `m_Size` 夹紧检查永远无法触发，解析器连续读取 ES 描述符 payload 边界之外的文件数据（相邻 box 的原始字节），并将这些字节解释为描述符 tag/size/payload，最终在堆上分配大小由攻击者控制的缓冲区（通过 `AP4_UnknownDescriptor::AP4_UnknownDescriptor` 中不检查返回值的 `m_Data.SetDataSize(payload_size)`），并将超出预期范围的文件数据写入这些缓冲区。
- **触发条件**: 构造包含 ESDescriptor 的 MP4 文件，将其 payload_size 设置为 3（仅覆盖 es_id(2B)+flags(1B)），而 flags 字节设置为 `0x20`（bits[7:5]=001，即 `AP4_ES_DESCRIPTOR_FLAG_STREAM_DEPENDENCY` 置位），使代码额外读取 2 字节的 `DependsOn` 字段（共消耗 5 字节），从而使 `3 - 5` 产生无符号下溢 `0xFFFFFFFE`；在 ESDescriptor 之后紧跟精心构造的字节作为"伪子描述符"的 tag+size 数据，以控制后续 heap 分配。
- **安全影响**: 至少可导致进程崩溃（DoS）；若攻击者精确控制 ESDescriptor 后相邻字节的 tag+size，可以（1）触发超大 heap 分配（OOM crash）；（2）使解析器读取属于其他 box 的数据并将其存入堆缓冲区（信息泄露），以及利用后续错误解析链触发进一步内存破坏（潜在 RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
