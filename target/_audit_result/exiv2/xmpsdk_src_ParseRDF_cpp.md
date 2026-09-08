Both recursive call chains are confirmed with no depth limit anywhere in the codebase. Here is the final audit report.

## VULN: Uncontrolled Recursion / Stack Overflow in RDF/XMP Parser
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement(), RDF_PropertyElementList(), RDF_PropertyElement(), RDF_ResourcePropertyElement(), RDF_ParseTypeResourcePropertyElement()
- **行号**: 693-707, 784-798, 851-925, 940-998, 1084-1113
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file (JPEG/PNG/TIFF/WEBP/HEIF etc. containing XMP metadata)
- **外部触发路径**: `exiv2 pr <file>` → `Image::readMetadata()` → format-specific reader (e.g. `JpegBase::readMetadata()`) → XMP APP1 extraction → `XMPMeta::ParseFromBuffer()` (XMPMeta-Parse.cpp:1093) → `ProcessRDF(&this->tree, *xmlRoot, options)` (XMPMeta-Parse.cpp:1270) → `RDF_RDF()` → `RDF_NodeElementList()` → **[recursive descent begins]** `RDF_NodeElement()` → `RDF_PropertyElementList()` → `RDF_PropertyElement()` → `RDF_ResourcePropertyElement()` (line 916) → `RDF_NodeElement()` (line 987, recursive); 第二路径: `RDF_PropertyElement()` → `RDF_ParseTypeResourcePropertyElement()` (line 888) → `RDF_PropertyElementList()` (line 1107, recursive)
- **描述**: ParseRDF.cpp 实现了一个针对 RDF/XML 语法的递归下降解析器，用于解析图像文件中嵌入的 XMP 元数据。存在两条相互递归的调用链均无任何深度限制：**路径1**：`RDF_NodeElement`(693)→`RDF_PropertyElementList`(704)→`RDF_PropertyElement`(795)→`RDF_ResourcePropertyElement`(916)→`RDF_NodeElement`(987)；**路径2**：`RDF_PropertyElement`(888)→`RDF_ParseTypeResourcePropertyElement`(1107)→`RDF_PropertyElementList`→`RDF_PropertyElement`(888)。整个 xmpsdk 源码中不存在任何递归深度计数器、最大深度限制、栈深度检查，也未设置 expat 解析器的最大嵌套深度（ExpatAdapter.cpp 中也未调用任何相关 API）。XML 树先由 expat 完整构建后，`ProcessRDF` 再对其进行递归遍历。每一个 RDF 嵌套层级在路径1上消耗约 4 个栈帧，在路径2上消耗约 3 个栈帧，每帧约 100–300 字节。当 XMP 嵌套达到数千层时，C 调用栈（默认 8 MB）被耗尽，导致栈溢出。
- **触发条件**: 攻击者构造一个合法格式的图像文件（JPEG、PNG、TIFF 等），在其 XMP 元数据包中嵌入深度嵌套的 RDF 结构。路径1示例：数千层 `<rdf:Description>` 内包含 `<ns:prop><rdf:Description>...</rdf:Description></ns:prop>` 的嵌套。路径2示例：数千层 `<ns:prop rdf:parseType="Resource"><ns:inner rdf:parseType="Resource">...</ns:inner></ns:prop>` 的嵌套。文件大小可以很小（递归层次靠大量开/闭标签堆积，实际内容极少），无需任何认证，exiv2 读取该文件时即触发。
- **安全影响**: 最坏情况：进程栈溢出崩溃（DoS）。在以共享库方式嵌入 exiv2 的 Web 服务或批处理服务中（如图片上传服务、CMS、数字资产管理平台），攻击者可通过上传构造的图像远程触发服务进程崩溃（AV:N），造成持续性拒绝服务。在特定平台/编译器配置下，栈溢出覆盖相邻内存区域可能进一步转化为远程代码执行（RCE），但这依赖平台实现细节。

<!-- AUDIT_PROMPT_VERSION: 1 -->
