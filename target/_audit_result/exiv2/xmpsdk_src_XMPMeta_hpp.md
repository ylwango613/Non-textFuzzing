I have all the information needed. Let me produce the final report.

## VULN: Unbounded mutual recursion in XMP RDF parser causes stack overflow (DoS)
- **漏洞类别**: memory-safety
- **函数**: `RDF_NodeElement()`, `RDF_PropertyElementList()`, `RDF_PropertyElement()`, `RDF_ResourcePropertyElement()`
- **行号**: ParseRDF.cpp:693-707, 785-798, 851-925, 941-998; XMPMeta-Parse.cpp:110-137
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file (JPEG/TIFF/PNG/etc.) with deeply nested XMP RDF payload
- **外部触发路径**: `exiv2 pr <file>` → `Image::readMetadata()` → `XmpParser::decode()` (xmp.cpp:663) → `SXMPMeta meta(xmpPacket.data(), len)` (xmp.cpp:690) → `XMPMeta::ParseFromBuffer()` (XMPMeta-Parse.cpp:1093) → `ExpatAdapter::ParseBuffer()` (expat 2.4.7, no nesting depth limit) → `ProcessRDF()` (ParseRDF.cpp:623) → `RDF_RDF()` → `RDF_NodeElementList()` (ParseRDF.cpp:661) → `RDF_NodeElement()` (ParseRDF.cpp:693) → `RDF_PropertyElementList()` (ParseRDF.cpp:704) → `RDF_PropertyElement()` (ParseRDF.cpp:795) → `RDF_ResourcePropertyElement()` (ParseRDF.cpp:916) → `RDF_NodeElement()` (ParseRDF.cpp:987) — unbounded cycle
- **描述**: `ParseRDF.cpp` 中存在无深度限制的相互递归调用链：`RDF_NodeElement`（line 693）调用 `RDF_PropertyElementList`（line 704），后者调用 `RDF_PropertyElement`（line 795），后者在处理 resource property element 时调用 `RDF_ResourcePropertyElement`（line 916），而该函数在 line 987 再次调用 `RDF_NodeElement`，形成闭合环路。此外，`RDF_ParseTypeResourcePropertyElement`（line 1085）在 line 1107 直接回调 `RDF_PropertyElementList`，构成第二条递归路径。任何一条路径上均无深度计数器或栈保护。`PickBestRoot`（XMPMeta-Parse.cpp:110-137）在 rootCount > 1 时也对整个 XML 树进行无深度限制的递归遍历（line 131）。系统上 expat 2.4.7 没有元素嵌套深度限制（该限制直到 expat 2.6.0 才引入），因此攻击者可以构造任意深度嵌套的 XMP/RDF XML，令以上递归函数耗尽进程栈空间，导致 SIGSEGV 崩溃。
- **触发条件**: 在 JPEG APP1 标记（"http://ns.adobe.com/xap/1.0/" 前缀）、TIFF 700 号标签、PNG iTXt 块或其他支持格式的 XMP 数据包中嵌入约 5000–10000 层深度的嵌套 RDF 结构，例如：`<rdf:Description><ns:Prop rdf:parseType="Resource"><rdf:Description>...</rdf:Description></ns:Prop></rdf:Description>` 重复嵌套至目标深度。无需任何特殊权限，普通用户文件即可触发。
- **安全影响**: 进程崩溃（DoS）；在某些部署场景（服务端图像处理管道）中，攻击者可通过上传一张图片使整个处理进程反复崩溃，造成持续性服务不可用。栈耗尽通常不可控地写入栈保护页外的内存，在无保护的嵌入式或旧版内核环境中理论上可能被利用为 RCE，但主要安全影响为 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
