Based on my comprehensive analysis of `Ap4Expandable.h` and all related implementation files, I have traced the complete parsing paths through `AP4_EsDescriptor`, `AP4_DecoderConfigDescriptor`, `AP4_ObjectDescriptor`, and `AP4_UnknownDescriptor`. Here are the confirmed memory safety findings:

## VULN: DecoderConfigDescriptor SubStream integer underflow → OOB stream read
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()
- **行号**: 92-92
- **CWE**: CWE-191 (Integer Underflow / Wrap-Around)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File() → AP4_Movie → AP4_Track → moov/trak/mdia/minf/stbl/stsd/mp4a → AP4_EsdsAtom → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_DecoderConfigDescriptor(stream, header_size, payload_size) → Ap4DecoderConfigDescriptor.cpp:92
- **描述**: 在 `AP4_DecoderConfigDescriptor` 解析构造函数中，以文件字段 `payload_size`（`AP4_Size` = uint32）减去常数 13 来计算子流大小：`new AP4_SubStream(stream, start+13, payload_size-13)`。当攻击者将 `payload_size` 设置为小于 13 的值（如 0 或 1），无符号减法发生下溢，结果回绕至约 4GB（如 `payload_size=0` 时结果为 `0xFFFFFFF3`）。该巨型 SubStream 被传入 `CreateDescriptorFromStream` 循环中，使其无边界约束地从文件中声明的 DecoderConfig 描述符边界外继续读取相邻的 MP4 数据，将其当作合法子描述符解析。
- **触发条件**: 构造一个 MP4 文件，其 moov/trak/mdia/minf/stbl/stsd/mp4a/esds 原子中包含 `AP4_DecoderConfigDescriptor`，令该描述符头部声明的 `payload_size < 13`（例如设置为 0x00）。
- **安全影响**: 越界读取相邻 MP4 盒子数据并将其解析为子描述符，造成信息泄露；若相邻数据恰好编码大 `payload_size`，将触发数百 MB 级大内存分配，导致 `std::bad_alloc` 崩溃（DoS）；亦可引发无限循环解析直至文件末尾（CPU DoS）。

## VULN: EsDescriptor SubStream integer underflow → OOB stream read
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor()
- **行号**: 103-103
- **CWE**: CWE-191 (Integer Underflow / Wrap-Around)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File() → AP4_EsdsAtom → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_EsDescriptor(stream, header_size, payload_size) → Ap4EsDescriptor.cpp:103
- **描述**: `AP4_EsDescriptor` 解析构造函数先读取 es_id（2字节）、flags（1字节）、可选的 DependsOn（2字节）、URL（1+N字节）以及 OcrEsId（2字节，因存在 flag 判断 bug 在 URL flag 置位时无条件读取），再以 `payload_size - AP4_Size(offset-start)` 计算剩余字节数构建 SubStream。若因 URL flag 触发而消耗字节数超过 `payload_size` 声明值，则 `AP4_Size` 无符号减法下溢回绕至约 4GB，产生巨型 SubStream，使后续 `CreateDescriptorFromStream` 无限制地读取并解析相邻 MP4 数据。该 bug 因代码第 93 行错误地用 `AP4_ES_DESCRIPTOR_FLAG_URL` 替代 `AP4_ES_DESCRIPTOR_FLAG_OCR_STREAM` 来触发 OcrEsId 读取而更易被利用。
- **触发条件**: 构造一个 EsDescriptor，令 `payload_size = 5`，同时将 flags 字节设置为 0x40（URL flag）并令 `url_length = 0`，使实际消耗字节为 2+1+1+0+2=6 > payload_size=5，触发下溢。
- **安全影响**: 越界读取相邻 MP4 盒子内容并作为子描述符解析（信息泄露）；若相邻数据构造为大 payload_size 描述符，触发大内存分配导致 `bad_alloc` 崩溃（DoS）；对文件尾后方位置的无约束读循环导致 CPU 资源耗尽（DoS）。

## VULN: ObjectDescriptor SubStream integer underflow → OOB stream read
- **漏洞类别**: memory-safety
- **函数**: AP4_ObjectDescriptor::AP4_ObjectDescriptor()
- **行号**: 96-96
- **CWE**: CWE-191 (Integer Underflow / Wrap-Around)
- **CVSS v3.1**: 6.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File() → AP4_IodsAtom 或 OD command → AP4_DescriptorFactory::CreateDescriptorFromStream() → AP4_ObjectDescriptor(stream, tag, header_size, payload_size) → Ap4ObjectDescriptor.cpp:96
- **描述**: `AP4_ObjectDescriptor` 解析构造函数在读取可变长度字段（ID+flags 2字节，可选 url_length 1字节 + url_bytes N字节）后，用 `payload_size - AP4_Size(offset-start)` 计算子流大小。若 URL flag 置位且 `payload_size` 过小（小于实际消耗字节数），unsigned 减法下溢产生约 4GB 大小的 SubStream，使解析循环越界读取相邻 MP4 数据。
- **触发条件**: 构造 ObjectDescriptor，令 `payload_size = 2`，bits 字段中 URL flag（第5位）置位，`url_length = 1`，则消耗 2+1+1=4 字节 > payload_size=2，触发下溢。
- **安全影响**: 越界读取相邻文件数据作为子描述符（信息泄露）；引发大内存分配导致 `bad_alloc`（DoS）；无约束解析循环直至 EOF（CPU DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
