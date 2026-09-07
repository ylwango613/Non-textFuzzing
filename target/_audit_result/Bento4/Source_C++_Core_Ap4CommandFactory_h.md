I now have complete context. Let me write the final audit report.

## VULN: Integer Underflow in AP4_ObjectDescriptor Substream Size → Out-of-Bounds Read
- **漏洞类别**: memory-safety
- **函数**: AP4_ObjectDescriptor::AP4_ObjectDescriptor()
- **行号**: 95-96 (Ap4ObjectDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) / CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4 output.aac` → `new AP4_File(*input)` → `AP4_Movie` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_IodsAtom::Create(size_32, stream)` → `AP4_IodsAtom::AP4_IodsAtom` → `AP4_DescriptorFactory::CreateDescriptorFromStream(stream, descriptor)` (line 76, using unbounded main file stream) → `new AP4_ObjectDescriptor(stream, tag, header_size, payload_size)` (Ap4DescriptorFactory.cpp:84, stream NOT bounded to payload_size) → constructor reads bits(2B) + url_length(1B) + URL(url_length bytes) from unbounded file stream → `payload_size - AP4_Size(offset-start)` at Ap4ObjectDescriptor.cpp:95-96 underflows → `new AP4_SubStream(stream, offset, ~0xFFFFFFxx)` (virtual ~4 GB substream) → descriptor parse loop reads file bytes far beyond iods atom boundary
- **描述**: 在 `AP4_ObjectDescriptor::AP4_ObjectDescriptor`（Ap4ObjectDescriptor.cpp 第 95-96 行）中，子流大小通过无符号减法 `payload_size - AP4_Size(offset - start)` 计算，其中 `payload_size` 来自文件中 OD 描述符的 Expandable 编码字段（最大 268,435,455），而 `offset - start` 为在构造函数中已从流中读取的字节数（2 字节 bits + 1 字节 url_length + url_length 字节 URL 数据 = 3 + url_length）。关键缺陷：`AP4_DescriptorFactory::CreateDescriptorFromStream`（Ap4DescriptorFactory.cpp:84）将**未限定**的主文件流（而非以 payload_size 为界的子流）直接传递给 `AP4_ObjectDescriptor` 构造函数，使构造函数可以从文件流中读取任意数量的 URL 字节（最多 255 字节）。当 `3 + url_length > payload_size` 时，`payload_size - (3 + url_length)` 作为 `AP4_UI32` 无符号下溢，产生约 4 GB 的值，从而构造出一个声称大小为 ~4 GB 的 `AP4_SubStream`。后续描述符解析循环通过此虚假巨型子流读取 iods atom 边界之外的文件数据，将任意文件内容解析为 OD 子描述符（越界读）。
- **触发条件**: 构造 MP4 文件，其 `moov/iods` atom 中包含一个 OD 描述符（tag 0x01），Expandable 编码 payload_size 设为极小值（如 5），同时设置 url_flag=1 且 url_length=200（大于 payload_size - 3 = 2）。由于 iods 之后在文件流中存在真实数据，url 的 200 字节可被成功读入，触发 5 - 203 的无符号下溢。
- **安全影响**: 越界读取 iods atom 之外的任意 MP4 文件字节并将其解析为描述符结构，可导致：（1）信息泄露（读取和暴露后续 box 数据内容）；（2）若解析的越界数据中恰好编码了大 payload_size（Expandable 格式），触发高达 268 MB 的堆内存分配，造成内存耗尽 DoS；（3）在特定配置下可进一步引发二次解析漏洞（对越界数据进行类型匹配，触发更深层描述符的内存分配与读取）。

## VULN: Integer Underflow in AP4_InitialObjectDescriptor Substream Size → Out-of-Bounds Read
- **漏洞类别**: memory-safety
- **函数**: AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor()
- **行号**: 254-255 (Ap4ObjectDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) / CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: `mp42aac input.mp4 output.aac` → `new AP4_File(*input)` → `AP4_AtomFactory::CreateAtomFromStream` → `AP4_IodsAtom::Create(size_32, stream)` → `AP4_IodsAtom::AP4_IodsAtom` → `AP4_DescriptorFactory::CreateDescriptorFromStream(stream, descriptor)` (line 76) → `new AP4_InitialObjectDescriptor(stream, tag, header_size, payload_size)` (Ap4DescriptorFactory.cpp:89, 同样以未限定主文件流传入) → 构造函数读取 bits(2B) + url_length(1B) + URL(url_length B) + profiling fields(0 or 5B) from unbounded stream → `payload_size - AP4_Size(offset - start)` at Ap4ObjectDescriptor.cpp:254-255 下溢 → ~4 GB 子流 → 读取越出 iods atom 边界的文件数据
- **描述**: 与上述 `AP4_ObjectDescriptor` 漏洞完全对称，发生于 `AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor`（Ap4ObjectDescriptor.cpp 第 254-255 行）。IOD 描述符（tag 0x02/0x10）在设置 url_flag=1 时读取 bits(2B) + url_length(1B) + URL(url_length B)，未设置 url_flag 时额外读取 5 个 profile/level 字段（共 7B）。当已读字节数超过 Expandable 编码的 `payload_size` 时，`AP4_UI32` 无符号减法下溢至约 4 GB，生成虚假大小的 `AP4_SubStream`，使 `AP4_DescriptorFactory::CreateDescriptorFromStream` 在此子流上无界迭代，越界读取 iods atom 边界之后的文件数据。
- **触发条件**: 构造 MP4 文件 `moov/iods` atom 中包含 IOD 描述符（tag 0x02），payload_size 设为 4（小于 url_flag=1 路径所需最小 3 + url_length），url_length 设为最大值 255，使构造函数从未限定文件流读取 258 字节后尝试 `4 - 258` 触发下溢；或在 url_flag=0 路径设置 payload_size < 7（5 个 profile 字节 + 2 字节 bits = 7B 最小消耗）。
- **安全影响**: 同 AP4_ObjectDescriptor 漏洞：越界读取 iods atom 后的文件数据，触发对任意文件内容的描述符解析，潜在信息泄露、堆内存耗尽 DoS，在恶意构造的文件结构配合下可进一步扩大攻击面。

<!-- AUDIT_PROMPT_VERSION: 1 -->
