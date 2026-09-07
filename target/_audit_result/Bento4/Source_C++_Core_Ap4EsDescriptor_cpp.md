I now have enough context for a complete analysis. Here are the confirmed facts:

- `AP4_Size` = `AP4_UI32` (32-bit unsigned)
- `AP4_LargeSize` = 64-bit unsigned on 64-bit platforms
- `AP4_Position` = 64-bit unsigned
- In `AP4_EsDescriptor::AP4_EsDescriptor` (line 102–103): `payload_size - AP4_Size(offset-start)` is a 32-bit unsigned subtraction. If the consumed bytes exceed `payload_size`, it wraps to ~4 GB, which zero-extends to 64-bit when stored in `m_Size`.
- `AP4_SubStream::ReadPartial` and `Seek` enforce `m_Size` as the ceiling, not the outer container's size.
- The stream passed from `AP4_EsdsAtom` is the **unbounded** file stream (not wrapped in a SubStream bounded to the esds atom size).
- Maximum header bytes consumed: 2 (EsId) + 1 (bits) + 2 (DependsOn) + 1 (url_length) + 255 (url) + 2 (OcrEsId, read if URL flag set) = up to 263 bytes.
- If `payload_size < consumed_bytes`, the subtraction at line 103 wraps to a value near 4 GB.
- With `m_Size ≈ 4 GB`, the descriptor factory loop reads sub-descriptors arbitrarily far into the file stream, bounded only by actual file EOF—not by the ES descriptor's stated boundary.
- `AP4_UnknownDescriptor` and `AP4_DecoderSpecificInfoDescriptor` constructors allocate buffers sized by attacker-controlled `payload_size` (up to 268 MB from the expandable encoding), with read-return values ignored, so uninitialized bytes can surface in subsequent processing.

## VULN: Integer Underflow in EsDescriptor SubStream Size Enables OOB Stream Read
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor(AP4_ByteStream&, AP4_Size, AP4_Size)
- **行号**: 100-110
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → AP4_File::AP4_File → AP4_AtomFactory::CreateAtomFromStream → AP4_EsdsAtom::Create → AP4_DescriptorFactory::CreateDescriptorFromStream → AP4_EsDescriptor::AP4_EsDescriptor (unbounded file stream, line 102-103)
- **描述**: 在第 100–103 行，`offset-start`（已消耗的 payload 字节数）被转换为 `AP4_Size`（AP4_UI32，32 位无符号整型）并从同为 32 位无符号的 `payload_size` 中减去。若已消耗字节数超过 `payload_size`（例如：`payload_size=3` 但 STREAM_DEPENDENCY/URL 标志导致实际读取 5–263 字节），则 `payload_size - AP4_Size(offset-start)` 发生 32 位无符号下溢，结果约为 `0xFFFFFFF…`，零扩展为 64 位后作为 `AP4_LargeSize` 传入 `AP4_SubStream` 构造函数（第 102–103 行）。该 SubStream 的 `m_Size` 被设置为约 4 GB，而其底层容器是未经边界限制的文件流（`AP4_EsdsAtom::Create` 中传入的 `stream` 无 SubStream 包装）。后续 `while` 循环（第 105–109 行）通过此 SubStream 不断调用 `AP4_DescriptorFactory::CreateDescriptorFromStream`，可从 ES descriptor 边界之后的文件任意位置解析数据作为子描述符，直至文件 EOF。`AP4_UnknownDescriptor` 和 `AP4_DecoderSpecificInfoDescriptor` 构造函数忽略 `stream.Read` 返回值，导致被分配堆缓冲区的未初始化字节可被后续操作访问（CWE-908）。
- **触发条件**: 构造 esds atom，其内嵌 ES descriptor 的 expandable-size 字段（payload_size）声明值小于实际解析所消耗的字节数：设置 STREAM_DEPENDENCY 标志（消耗额外 2 字节），或同时设置 URL 标志（消耗额外 1+url_length+2 字节），使 `offset-start > payload_size`，触发 32 位下溢。一个有效的最小 PoC：payload_size=3，bits 字节设 STREAM_DEPENDENCY 位，后跟任意 2 字节 DependsOn。
- **安全影响**: (1) 越界读取文件流——ES descriptor 边界后的所有文件数据（其他 box/atom 内容）被解析为子描述符，导致信息泄露（攻击者可借助文件内容控制堆分配行为）；(2) 子描述符的 payload_size 最高可达 268 MB（expandable 编码上限），`AP4_UnknownDescriptor` 和 `AP4_DecoderSpecificInfoDescriptor` 均以此大小分配堆内存，而 `stream.Read` 返回值被忽略，导致已分配缓冲区含未初始化数据（CWE-908），在 write-back 路径中可造成信息泄露；(3) 循环创建大量堆对象，结合构造超大 payload_size 子描述符，可导致堆内存耗尽，进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
