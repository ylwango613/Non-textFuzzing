Now I have all the information needed. Let me verify the exact type chain for the underflow:

- `payload_size` → `AP4_Size` = `AP4_UI32` (unsigned 32-bit)
- `payload_size - 13` when `payload_size < 13`: wraps around in `AP4_UI32`, e.g. `5 - 13 = 0xFFFFFFF8`
- Passed as `AP4_LargeSize size` (= `unsigned long`, 64-bit on Linux) to `AP4_SubStream`: zero-extended to `0x00000000FFFFFFF8` ≈ 4 GB
- `AP4_SubStream::ReadPartial` clamps only to `m_Size` (now ~4 GB), not to the actual file region of the DecoderConfig descriptor
- The while loop in the constructor can now read bytes from **adjacent MP4 boxes** as if they were DecoderConfig sub-descriptors

This is the single confirmed memory-safety vulnerability. No other heap-corruption paths were found in this header/implementation pair (the `Inspect()` multiplication cannot overflow given the maximum descriptor payload size of `0x0FFFFFFF`).

## VULN: Integer Underflow in AP4_DecoderConfigDescriptor Stream Constructor Inflates SubStream Size to ~4 GB
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)
- **行号**: 92
- **CWE**: CWE-191 (Integer Underflow / Wraparound) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4 output.aac` → `AP4_File::AP4_File()` → `AP4_EsdsAtom` parsing `esds` box inside `mp4a` sample entry → `AP4_DescriptorFactory::CreateDescriptorFromStream()` dispatches on tag `0x04` → `new AP4_DecoderConfigDescriptor(stream, header_size, payload_size)` with attacker-controlled `payload_size < 13` → `Ap4DecoderConfigDescriptor.cpp:92`: `new AP4_SubStream(stream, start+13, payload_size-13)`
- **描述**: `payload_size` 是从 MP4 文件中的 MPEG-4 expandable-class 编码长度字段读取的 `AP4_Size`（即 `AP4_UI32`，无符号 32 位）。当攻击者将 DecoderConfig 描述符的 payload 长度设置为小于 13 的值（如 0～12）时，第 92 行的 `payload_size - 13` 在无符号 32 位算术下发生回绕（underflow）：例如 `payload_size = 0` → `0 - 13 = 0xFFFFFFF3`。该结果被隐式零扩展为 `AP4_LargeSize`（`unsigned long`，64 位，约 4 GB）传给 `AP4_SubStream` 构造函数，使其 `m_Size` 字段被设为约 4 GB。此后 `AP4_SubStream::ReadPartial` 的边界裁剪 `if (m_Position+bytes_to_read > m_Size)` 对实际文件数据量几乎无约束效果，导致构造函数中的 `while (CreateDescriptorFromStream(...))` 循环可从父流（文件流）中越过 DecoderConfig 描述符的实际结束边界，将相邻 box 的字节当作子描述符继续解析（越界读）。
- **触发条件**: 在 MP4 文件的 `moov/trak/mdia/minf/stbl/stsd/mp4a/esds` box 中，将 DecoderConfig 描述符（tag=0x04）的 payload_size 字段（expandable-class 编码）设为 0～12 中的任意值。
- **安全影响**: 越界读取相邻 box 数据并将其当作描述符解析——若相邻字节恰好使 `CreateDescriptorFromStream` 返回成功且生成 `AP4_DecoderSpecificInfoDescriptor`，则会以文件中任意字节为大小做 `new AP4_Byte[payload_size]`，可造成大量堆分配导致 DoS；同时越界读取可能泄露文件中本不属于该描述符上下文的数据（信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
