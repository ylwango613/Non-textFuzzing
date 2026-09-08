I have now completed the full analysis. Both WXMPMeta.cpp and its entire call chain through ParseFromBuffer have been reviewed. The WXMPMeta.cpp file itself is a thin C wrapper; memory-safety vulnerabilities lie in the parsing subsystem it delegates to. Two confirmed vulnerabilities with clear triggering paths from `WXMPMeta_ParseFromBuffer_1` follow.

## VULN: Unbounded Mutual Recursion in RDF Parser Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement() / RDF_ResourcePropertyElement() / RDF_ParseTypeResourcePropertyElement() / RDF_PropertyElementList() / RDF_PropertyElement()
- **行号**: ParseRDF.cpp:693-707 (RDF_NodeElement), 941-998 (RDF_ResourcePropertyElement), 1085-1113 (RDF_ParseTypeResourcePropertyElement), 785-798 (RDF_PropertyElementList), 852-924 (RDF_PropertyElement)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr \<file\> → Image::readMetadata() → Exiv2::XmpParser::decode() → WXMPMeta_ParseFromBuffer_1() [WXMPMeta.cpp:1265] → XMPMeta::ParseFromBuffer() [XMPMeta-Parse.cpp:1093] → ProcessRDF() [XMPMeta-Parse.cpp:1270] → RDF_RDF() [ParseRDF.cpp:645] → RDF_NodeElementList() [ParseRDF.cpp:662] → RDF_NodeElement() [ParseRDF.cpp:693] → RDF_PropertyElementList() [ParseRDF.cpp:704] → RDF_PropertyElement() [ParseRDF.cpp:852] → RDF_ResourcePropertyElement() [ParseRDF.cpp:941] → RDF_NodeElement() [ParseRDF.cpp:987, recursive] → … unbounded
- **描述**: The RDF parser in ParseRDF.cpp implements a recursive descent recognizer with two mutual-recursion cycles and no depth counter: (1) `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` → `RDF_NodeElement` (line 987), and (2) `RDF_ParseTypeResourcePropertyElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ParseTypeResourcePropertyElement` (line 1107). There is no guard variable, no maximum-depth check, and no iterative fallback anywhere in this call chain. Each recursion level allocates a new C stack frame. When the XML tree is deep enough, the stack is exhausted and the process receives SIGSEGV or equivalent, producing a stack-based memory corruption.
- **触发条件**: 攻击者在图像文件（JPEG/TIFF/PNG 等）中嵌入 XMP 数据包，XMP 内的 RDF 结构包含任意深层嵌套的 `<rdf:Description>` 子结构，或使用 `rdf:parseType="Resource"` 属性的深度嵌套属性元素。每个嵌套层级增加约 5 个栈帧（~200–500 字节），在默认 8 MB 栈上约需 2 万层即可溢出。紧凑的 `rdf:parseType="Resource"` 形式可大幅减少所需文件体积。
- **安全影响**: 确定性 DoS（process crash）。在未启用栈金丝雀或 ASLR 的平台上，栈溢出可覆盖返回地址，潜在实现任意代码执行（RCE）。在服务端图像批处理场景中（AV:N/UI:N），危害等级提升至 CVSS 7.5。

## VULN: Unbounded Recursion in PickBestRoot Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: PickBestRoot()
- **行号**: XMPMeta-Parse.cpp:110-137（递归调用位于第 118 行和第 131 行）
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file
- **外部触发路径**: exiv2 pr \<file\> → Image::readMetadata() → Exiv2::XmpParser::decode() → WXMPMeta_ParseFromBuffer_1() [WXMPMeta.cpp:1265] → XMPMeta::ParseFromBuffer() [XMPMeta-Parse.cpp:1093] → FindRootNode() [XMPMeta-Parse.cpp:1266] → PickBestRoot() [XMPMeta-Parse.cpp:154] → PickBestRoot() [recursive, line 118 or 131] → … unbounded
- **描述**: `PickBestRoot` 在 `xmlParser.rootCount > 1`（即 XMP 文档中出现多个 `rdf:RDF` 元素）时被调用，用于在整棵 XML 树中搜索最佳根节点。该函数对每个非目标子节点递归调用自身（第 131 行），且不携带任何深度参数或终止计数器。XML 树深度完全由攻击者控制——每增加一层 XML 嵌套，PickBestRoot 就新增一个栈帧，直至栈耗尽引发 SIGSEGV，造成栈内存破坏。
- **触发条件**: 攻击者在图像文件的 XMP 数据包中构造包含两个或以上 `rdf:RDF` 元素（触发 `rootCount > 1` 分支），同时在 `rdf:RDF` 之前或之内放置任意深层嵌套的 XML 元素（例如千层以上的任意命名空间元素）。Expat 在 XML 解析阶段本身不限制树深度，所以攻击者仅需将深度嵌套的 XML 写入图像 XMP 载荷即可。
- **安全影响**: 确定性 DoS（process crash via stack exhaustion）。在未充分启用栈保护的平台上，可能升级为 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
