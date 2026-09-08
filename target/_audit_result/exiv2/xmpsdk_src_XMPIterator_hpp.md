I've now fully analyzed `XMPIterator.hpp`, `XMPIterator.cpp`, `ParseRDF.cpp`, `XMPMeta-Parse.cpp`, and `ExpatAdapter.cpp`. Let me document the findings.

**Analysis summary:**
- `XMPIterator.hpp`/`.cpp`: The `IterPosStack ancestors` stores heap iterators (no stack risk). `AddNodeOffspring` never pushes to the vector being actively iterated. The `leafOffset` arithmetic stays within `[0, fullPath.size()]` by construction. No iterator invalidation or OOB found in the iterator itself.
- `ParseRDF.cpp`: The recursive descent RDF parser has **no depth limit**. The mutual recursion `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` → `RDF_NodeElement` (confirmed at lines 704→795→916→987→693) and the path `RDF_PropertyElement` → `RDF_ParseTypeResourcePropertyElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` (lines 888→1107→795→...) are unbounded. A crafted deeply-nested XMP document triggers unbounded stack growth.

## VULN: Unbounded Recursion in ParseRDF Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement() / RDF_ResourcePropertyElement() / RDF_ParseTypeResourcePropertyElement()
- **行号**: ParseRDF.cpp:693–707, 941–998, 1085–1113
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file (JPEG, PNG, TIFF, WEBP, PSD, JP2 containing malicious XMP packet)
- **外部触发路径**: `exiv2 pr <file>` → `JpegImage::readMetadata()` (jpgimage.cpp) → `XmpParser::decode()` (xmp.cpp:663) → `SXMPMeta` constructor → `XMPMeta::ParseFromBuffer()` (XMPMeta-Parse.cpp:1093) → `ProcessRDF()` (XMPMeta-Parse.cpp:1270 → ParseRDF.cpp:623) → `RDF_RDF()` → `RDF_NodeElementList()` → `RDF_NodeElement()` → `RDF_PropertyElementList()` → `RDF_PropertyElement()` → `RDF_ResourcePropertyElement()` → `RDF_NodeElement()` → ... (unbounded mutual recursion, no depth guard)
- **描述**: `ParseRDF.cpp` 中的递归下降 RDF 解析器存在互递归循环，且无任何深度限制。`RDF_NodeElement`（第 693 行）调用 `RDF_PropertyElementList`（第 704 行），后者调用 `RDF_PropertyElement`（第 795 行），再调用 `RDF_ResourcePropertyElement`（第 916 行），最终在第 987 行再次调用 `RDF_NodeElement`，形成无限制的互递归；`RDF_ParseTypeResourcePropertyElement`（第 1085 行）在第 1107 行调用 `RDF_PropertyElementList` 形成另一递归环路。当 XML 嵌套深度超过系统栈容量（默认 8 MB）时，大约 10,000–20,000 层嵌套即可耗尽栈空间，导致 SIGSEGV 崩溃（栈溢出触发的写 OOB 行为）。
- **触发条件**: 攻击者将包含大量嵌套 `rdf:Description` 元素的 XMP 数据包（例如：`<rdf:Description><dc:title><rdf:Alt><rdf:li><rdf:Description>...(~10000 层)...</rdf:Description></rdf:li></rdf:Alt></dc:title></rdf:Description>`）嵌入 JPEG APP1 段（或 PNG iTXt/PNG zTXt/TIFF XMP tag），提交给任何调用 exiv2 解析元数据的进程即可触发。
- **安全影响**: 最直接结果为进程崩溃（DoS）；在某些平台/编译配置下，栈溢出可覆盖相邻栈帧数据，理论上可升级至远程代码执行（若 exiv2 被集成进服务端图像处理管线）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
