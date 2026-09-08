Now I have all the context needed. Let me compile my complete findings from the full read and context analysis.

**Summary of analyzed code (2157 lines, XMPUtils.cpp + ParseRDF.cpp call chain):**

- **Lines 1-468**: Time utility functions, `GatherInt`, `FormatFullDateTime`, `DecodeBase64Char` — no exploitable issues found.
- **Lines 469-629**: `EstimateSizeForJPEG`, `MoveOneProperty`, `CreateEstimatedSizeMap`, `MoveLargestProperty` — **recursion without depth limit in `EstimateSizeForJPEG`**.
- **Lines 630-999**: Path composition functions, `ConvertFrom*` — `snprintf` with format from caller (not attacker-controlled from file). No exploitable issues.
- **Lines 1000-1430**: `ConvertToDate`, `ConvertToInt`/`Float`/`Bool` — no exploitable issues.
- **Lines 1430-1663**: `EncodeToBase64`, `DecodeFromBase64` — **OOB read in final-chunk loop of `DecodeFromBase64`**.
- **Lines 1664-2157**: `PackageForJPEG`, `MergeFromJPEG`, time zone functions — no additional issues.
- **ParseRDF.cpp (related context)**: **Unbounded mutual recursion** `RDF_NodeElement` ↔ `RDF_PropertyElementList` ↔ `RDF_PropertyElement` ↔ `RDF_ResourcePropertyElement` — stack overflow on crafted deeply nested XMP.

## VULN: Stack Overflow via Unbounded Recursion in XMP RDF Parser
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement() / RDF_PropertyElementList() / RDF_PropertyElement() / RDF_ResourcePropertyElement() / RDF_ParseTypeResourcePropertyElement()
- **行号**: ParseRDF.cpp:693-707, 785-798, 852-925, 941-998, 1085-1113
- **CWE**: CWE-674 (Uncontrolled Recursion) / CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: `exiv2 pr <file>` → `JpegImage::readMetadata()` → XMP APP1 segment extraction → `XmpParser::decode()` → `SXMPMeta meta(xmpPacket.data(), len)` (XMPMeta constructor calls ParseFromBuffer) → expat-built XML_Node tree → `RDF_RDF()` → `RDF_NodeElementList()` → `RDF_NodeElement()` → `RDF_PropertyElementList()` → `RDF_PropertyElement()` → `RDF_ResourcePropertyElement()` or `RDF_ParseTypeResourcePropertyElement()` → `RDF_NodeElement()` (cycle repeats without bound)
- **描述**: The XMP RDF parser in ParseRDF.cpp implements a mutually recursive descent that has no depth limit. Two distinct cycles exist: (1) `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` → `RDF_NodeElement`; and (2) `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ParseTypeResourcePropertyElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` (cycle). Each level of nested RDF struct (`rdf:parseType="Resource"` or `rdf:Description`-wrapped arrays) consumes one stack frame. With arbitrarily deep nesting, the call stack is exhausted, overwriting adjacent stack frames and corrupting the thread's stack.
- **触发条件**: 攻击者构造一个 JPEG/TIFF/PNG 文件，其 XMP 段包含深度嵌套的 RDF 结构体，例如 `<ex:prop rdf:parseType="Resource"><ex:inner rdf:parseType="Resource">...` 嵌套几千层，或使用 `rdf:Bag`/`rdf:Seq` 包含 `rdf:Description` 子元素的深度嵌套。需要的嵌套深度约为 ~10,000–50,000 层（取决于系统栈大小，通常为 8 MB）。无需身份验证，文件可直接传给 `exiv2 pr`。
- **安全影响**: 栈内存耗尽并溢出导致进程崩溃（DoS），在特定栈布局下攻击者可覆盖返回地址或函数指针，可能实现任意代码执行（RCE）。

## VULN: Stack Overflow via Unbounded Recursion in EstimateSizeForJPEG
- **漏洞类别**: memory-safety
- **函数**: EstimateSizeForJPEG()
- **行号**: 477-514
- **CWE**: CWE-674 (Uncontrolled Recursion) / CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file
- **外部触发路径**: 任何调用 `SXMPUtils::PackageForJPEG()` 的应用 → `XMPUtils::PackageForJPEG()` → `CreateEstimatedSizeMap()` → `EstimateSizeForJPEG(stdProp)` (对每个顶层属性调用) → 对 `xmpNode->children[i]` 递归调用 `EstimateSizeForJPEG()` (lines 497, 507)，无深度限制
- **描述**: `EstimateSizeForJPEG` 递归地遍历 XMP 节点树来估算序列化大小。对于数组节点（`XMP_PropIsArray`），循环 `for (i < arraySize) estSize += EstimateSizeForJPEG(xmpNode->children[i])` (line 497) 对每个子节点递归；对于结构体节点，对每个字段同样递归 (line 507)。没有任何深度计数器或递归上界。由于 XMP 树是由 ParseRDF 同等地不受限制地构建的，攻击者可以通过嵌入深层嵌套 XMP 来驱动任意深度的递归。
- **触发条件**: 攻击者构造包含深度嵌套 XMP 数组/结构体的图像文件（JPEG、TIFF 等），然后目标应用读取该文件的 XMP 数据，再调用 `PackageForJPEG` 将 XMP 重新打包（例如在写入 JPEG 时）。嵌套深度约 ~10,000 层可触发 8MB 默认栈的溢出。
- **安全影响**: 栈溢出导致进程崩溃（可靠的 DoS），在特定情况下可能实现代码执行。

## VULN: Out-of-Bounds Read in DecodeFromBase64 Final-Chunk Loop
- **漏洞类别**: memory-safety
- **函数**: XMPUtils::DecodeFromBase64()
- **行号**: 1629-1635
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted image file
- **外部触发路径**: 使用 XMP SDK API 的应用读取含 XMP 属性的图像文件 → 应用调用 `SXMPUtils::DecodeFromBase64(encodedStr, encodedLen, ...)` 对 XMP 属性的 base64 值解码 → `XMPUtils::DecodeFromBase64()` 的最终块处理循环 (line 1630) → 当 `inStr` 超过 `encodedLen` 时，`DecodeBase64Char(encodedStr[inStr])` 越界读取
- **描述**: 在 `DecodeFromBase64` 的最终块处理循环中（lines 1630-1635），循环条件仅检查 `inChunk < 4-padding`（即需要的数据字节数），在每次迭代中无条件递增 `inStr`，并跳过空白字符（`0xFF`）而不退出。如果攻击者在最终 base64 数据块中嵌入空白字符（如空格、制表符、换行符），使得在 `inStr = inLimit` 处开始的区域中有效数据字符不足 `4-padding` 个，则循环会推进 `inStr` 到 `encodedLen` 之外，从 `encodedStr[encodedLen]` 开始越界读取内存。这是一个一次性越界读（OOB read），读取的字节决定了后续行为：若为有效 base64 字符则静默产生错误输出；若为其他字节则抛出异常。
- **触发条件**: 攻击者构造包含 XMP base64 属性值的图像文件，该值在最终 4 字节 base64 分组内包含空白字符，且最终分组末尾有效数据字符不足。例如：最终分组为 `"EF G"` (E、F 是有效字符、中间空格、G 是有效字符，最后一个有效字符在末尾但总数不够)，迫使循环越过 `encodedLen`。目标应用须调用 `DecodeFromBase64` 处理该值（exiv2 本身不调用此函数，但使用 XMP SDK 的其他应用会）。
- **安全影响**: 越界读取 `encodedStr` 后方最多几字节内存，可泄露相邻堆数据（信息泄露）；若后方字节为有效 base64 字符则产生错误的解码输出；在极端情况下（如攻击者能控制相邻内存）可进一步利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
