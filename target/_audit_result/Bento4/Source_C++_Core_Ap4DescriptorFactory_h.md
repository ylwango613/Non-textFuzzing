I now have enough context. Let me write the final audit report.

## VULN: Integer Underflow in AP4_DecoderConfigDescriptor Creates Oversize SubStream (OOB Read)
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()
- **行号**: 92 (Ap4DecoderConfigDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.6 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac(input.mp4) → AP4_File::AP4_File() → AP4_AtomFactory → moov/trak/mdia/minf/stbl/stsd → esds box → AP4_EsdsAtom → AP4_DescriptorFactory::CreateDescriptorFromStream() [tag=0x04 DecoderConfig] → AP4_DecoderConfigDescriptor(stream, header_size, payload_size=N<13) → `new AP4_SubStream(stream, start+13, payload_size-13)` 下溢
- **描述**: `AP4_DecoderConfigDescriptor` 构造函数在创建用于解析子描述符的 `AP4_SubStream` 时，直接计算 `payload_size - 13`（`AP4_UI32` 减法），而未检查 `payload_size >= 13`。当攻击者在 MP4 文件中构造 payload_size < 13 的 DecoderConfig 描述符时，该减法发生无符号下溢，例如 `payload_size=0` 时结果为 `0xFFFFFFF3`。这个下溢值被隐式转换为 `AP4_LargeSize`（uint64）并传入 SubStream 构造函数，使 SubStream 的 `m_Size` 被设置为约 4GB（`0xFFFFFFF3`）。随后的 while 循环调用 `CreateDescriptorFromStream` 从这个错误 SubStream 中持续读取，越过 DecoderConfig 描述符的声明边界，将属于相邻描述符或其他 box 的字节当作子描述符数据解析。攻击者可以在越界区域放置编码为大 payload_size（最大 268MB）的虚假描述符，触发 `SetDataSize` 执行 `new AP4_Byte[268MB]`，导致进程因 `std::bad_alloc` 崩溃。
- **触发条件**: 构造一个 MP4 文件，使 `esds` box 中的 ES_Descriptor 包含一个 tag=0x04（DecoderConfigDescriptor）、payload_size < 13（如 0 或 5）的描述符；在 DecoderConfig 声明区域之外（相邻字节）放置伪造的描述符头，其 expandable size 字段编码为接近 0x0FFFFFFF 的大值。
- **安全影响**: 确定性拒绝服务（进程崩溃）；越界读取相邻 box 数据（潜在信息泄露）；若结合堆风水可进一步利用。

## VULN: Integer Underflow in AP4_EsDescriptor Creates Oversize SubStream (OOB Read)
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor()
- **行号**: 102-103 (Ap4EsDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.6 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac(input.mp4) → AP4_File → esds box → AP4_EsdsAtom → AP4_DescriptorFactory::CreateDescriptorFromStream() [tag=0x03 ES_Descriptor] → AP4_EsDescriptor(stream, header_size, payload_size=N) → 解析 EsId(2B)+bits(1B)+可选 DependsOn(2B)/URL fields → `stream.Tell(offset)` → `new AP4_SubStream(stream, offset, payload_size-AP4_Size(offset-start))` 下溢
- **描述**: `AP4_EsDescriptor` 构造函数在记录起始位置 `start` 后，依次读取 EsId（2字节）、flags/priority 字节（1字节），并根据 flags 有条件地读取额外字段：`STREAM_DEPENDENCY` flag 额外读 2 字节 `m_DependsOn`，`URL` flag 额外读 `url_length`（1字节）+ URL 数据 + `m_OcrEsId`（2字节）。然后通过 `stream.Tell(offset)` 取当前位置计算已消耗字节数 `offset-start`，直接执行 `payload_size - AP4_Size(offset-start)`（AP4_UI32 减法）。由于 `stream`（工厂传入，未被 payload_size 限定边界）允许读越界，实际消耗字节数可超过 `payload_size`，导致 `AP4_UI32` 下溢到约 4GB，创建过大 SubStream，后续 while 循环越界解析相邻 box 数据。相同漏洞模式也存在于 `AP4_ObjectDescriptor::AP4_ObjectDescriptor()`（Ap4ObjectDescriptor.cpp:95-96），可通过 UrlFlag=1 且 url_length 较大触发。
- **触发条件**: 构造 ES_Descriptor，payload_size=4，bits 字节设置 `STREAM_DEPENDENCY` flag（bit5=1），使解析函数消耗 EsId(2)+bits(1)+DependsOn(2)=5 字节，而 payload_size=4，导致 `4-5` 下溢；或设置 `URL` flag（bit6=1）并将 payload_size 设为小于消耗字节数的值。在越界区域放置大 payload_size 的虚假子描述符触发大内存分配。
- **安全影响**: 确定性拒绝服务（进程崩溃于 bad_alloc）；越界读取相邻内存布局数据（信息泄露）。

## VULN: Wrong fields_size Accounting in AP4_IpmpDescriptor Causes 16-Byte OOB Read
- **漏洞类别**: memory-safety
- **函数**: AP4_IpmpDescriptor::AP4_IpmpDescriptor()
- **行号**: 130-140 (Ap4Ipmp.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 4.4 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac → esds → ES_Descriptor → ObjectDescriptor → AP4_DescriptorFactory::CreateDescriptorFromStream() [tag=0x0B IPMP_DESCRIPTOR] → AP4_IpmpDescriptor(stream, header_size, payload_size) → 固定字段读取后 fields_size 计算错误 → stream.Read 越界
- **描述**: 在 `m_DescriptorId == 0xFF && m_IpmpsType == 0xFFFF` 分支中，构造函数初始化 `fields_size = 3+3 = 6`，然后从 stream 连续读取：`m_DescriptorIdEx`（2字节）、`m_ToolId`（16字节）、`m_ControlPointCode`（1字节），总计 22 字节固定字段（含已读入的 m_DescriptorId 和 m_IpmpsType 各 1/2 字节合计 3 字节）。但 `fields_size` 仅记录了 6（或 7），遗漏了 m_ToolId 的 16 字节。后续判断 `if (fields_size < payload_size)` 后，执行 `m_Data.SetDataSize(payload_size-fields_size)` 分配缓冲区并 `stream.Read(m_Data.UseData(), payload_size-fields_size)` 读取数据，读取量比合法剩余字节多出 16 字节，导致 stream 消费超出 IPMP 描述符声明的 payload 区域，将相邻描述符/box 的原始字节读入 `m_Data` 堆缓冲区。
- **触发条件**: 构造包含 IPMP 描述符的 MP4 文件：`m_DescriptorId=0xFF`，`m_IpmpsType=0xFFFF`，`m_ControlPointCode=0`，`payload_size >= 7`（例如 payload_size=30）。实际剩余合法数据为 `payload_size-22=8` 字节，但代码尝试读取 `payload_size-6=24` 字节，将额外 16 字节从相邻结构读入堆缓冲区。
- **安全影响**: 信息泄露（相邻描述符或 box 数据泄入堆对象）；导致 IPMP 描述符数据被错误内容填充，可能触发后续解析逻辑异常；若相邻数据被攻击者精确控制可进一步利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
