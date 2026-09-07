I've completed the full analysis pass. Let me now confirm the line references one final time before writing the report.

Group 1 (lines 68–104): `AP4_ObjectDescriptor` stream constructor — the `payload_size - AP4_Size(offset-start)` calculation at line 96.

Group 2 (lines 215–263): `AP4_InitialObjectDescriptor` stream constructor — same calculation at line 254.

Both are confirmed integer underflow → oversized `AP4_SubStream` → OOB read of file data outside the declared descriptor payload, exploitable via a crafted iods box.

## VULN: Integer Underflow in AP4_ObjectDescriptor Stream Constructor via url_length
- **漏洞类别**: memory-safety
- **函数**: AP4_ObjectDescriptor::AP4_ObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)
- **行号**: 68-104 (Ap4ObjectDescriptor.cpp, class declared in Ap4ObjectDescriptor.h)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_IodsAtom::Create() → AP4_IodsAtom::AP4_IodsAtom(size,version,flags,stream) → AP4_DescriptorFactory::CreateDescriptorFromStream(*stream, descriptor) [tag=0x01/0x11, payload_size=attacker-controlled-small] → AP4_ObjectDescriptor::AP4_ObjectDescriptor(stream, tag, header_size, payload_size) → line 96: `new AP4_SubStream(stream, offset, payload_size - AP4_Size(offset-start))`
- **描述**: 在 `AP4_ObjectDescriptor` 的流式构造函数中，`payload_size` 来自文件字段（最大 ~268MB，通过 MPEG-4 可扩展长度编码），而 `m_UrlFlag` 和 `url_length` 也均来自文件字节。当 `m_UrlFlag=1` 时，构造函数从**无边界**的原始文件流中读取 `2 + 1 + url_length`（最多 258）字节的字段；随后在计算子描述符子流大小时执行 `payload_size - AP4_Size(offset-start)`。若 `(offset-start) > payload_size`（攻击者令 `payload_size=3`、`url_length=255` 即可），AP4_Size（uint32）做无符号减法产生整数下溢，结果约为 `0xFFFFFF01`，被提升为 `AP4_LargeSize`（uint64）传入 `AP4_SubStream` 构造函数，令 `m_Size ≈ 4 GB`。该超大 SubStream 的 `ReadPartial` 越界校验(`m_Position+bytes_to_read > m_Size`)几乎永不触发，使后续的子描述符解析 while 循环无约束地读取超出声明 `payload_size` 范围的文件字节，并将其解释为嵌套描述符。若越界区域恰好含有攻击者构造的大 `payload_size` 值，`AP4_UnknownDescriptor` 或 `AP4_DecoderSpecificInfoDescriptor` 会对其调用 `new AP4_Byte[payload_size]`，触发大量内存分配，导致 std::bad_alloc 未捕获崩溃（DoS）或读取任意文件区域数据作为描述符内容（信息泄露）。
- **触发条件**: 在 MP4 文件的 `moov/iods` box 中放置一个 OD 描述符（tag=0x01 或 0x11），令其 `payload_size` < 实际需读字节数（如 `payload_size=3`），并将 URL_flag bit 置 1、`url_length` 设为任意值（如 0x0A–0xFF）；在 URL 数据之后（即 `payload_size` 声明边界之外）的位置嵌入任意构造的"嵌套描述符"字节序列。
- **安全影响**: 进程崩溃（DoS）：若越界数据编码大型 payload_size 则触发 OOM；越界文件数据读取（信息泄露）：file-mapped 内存中超出描述符边界的字节被解析并可能影响后续逻辑；最坏情况下，若进一步触发内层解析器的堆分配漏洞，可能升级为堆损坏（RCE 风险）。

## VULN: Integer Underflow in AP4_InitialObjectDescriptor Stream Constructor via url_length
- **漏洞类别**: memory-safety
- **函数**: AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor(AP4_ByteStream&, AP4_UI08, AP4_Size, AP4_Size)
- **行号**: 215-263 (Ap4ObjectDescriptor.cpp, class declared in Ap4ObjectDescriptor.h)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_IodsAtom::Create() → AP4_IodsAtom::AP4_IodsAtom(size,version,flags,stream) → AP4_DescriptorFactory::CreateDescriptorFromStream(*stream, descriptor) [tag=0x02/0x10, payload_size=attacker-controlled-small] → AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor(stream, tag, header_size, payload_size) → line 254: `new AP4_SubStream(stream, offset, payload_size - AP4_Size(offset-start))`
- **描述**: `AP4_InitialObjectDescriptor` 的流式构造函数与 `AP4_ObjectDescriptor` 存在相同的整数下溢缺陷。当文件中的 IOD 描述符（tag=0x02/0x10）的 `m_UrlFlag=1` 时，构造函数从无边界流中读取 `2+1+url_length` 字节；若 `url_length`（来自文件，范围 0–255）使消耗字节数超过声明的 `payload_size`，则 `payload_size - AP4_Size(offset-start)` 发生 uint32 下溢（如 `payload_size=3`, `url_length=10`：消耗 13 字节，下溢为 `0xFFFFFFF6`），生成 `m_Size ≈ 4GB` 的 AP4_SubStream。后续的子描述符 while 解析循环在该越界 SubStream 上无限制运行，读取超出 IOD 声明边界的文件数据作为嵌套描述符。当越界数据编码合法描述符头时，各具体描述符构造函数（AP4_UnknownDescriptor、AP4_EsDescriptor 等）被递归调用，并可根据攻击者精心布置的 payload_size 值触发大内存分配（`new AP4_Byte[N]`，N 最大 ~268MB），引发进程崩溃或堆损坏。
- **触发条件**: 在 MP4 文件的 `moov/iods` box 中放置一个 IOD 描述符（tag=0x02 或 0x10），令 `payload_size` 小于 `2+1+url_length`（如 `payload_size=3`, `url_length=0x0A`），URL_flag bit 置 1；在 URL 字节之后的文件区域中布置任意"嵌套描述符"字节，供越界解析时命中。
- **安全影响**: 与 AP4_ObjectDescriptor 相同：DoS（进程崩溃，OOM 触发 uncaught std::bad_alloc）、越界文件数据泄露（信息泄露），以及通过精心构造的越界描述符数据可能进一步引发堆损坏（潜在 RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
