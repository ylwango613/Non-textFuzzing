I now have a complete picture. Let me write the final analysis.

**Batch 1 analysis (XML_Node.cpp lines 1–463):**
- `CollectNamespaceDecls` line 330: `while ( node.name[nameMid] != ':' ) ++nameMid;` — no bounds check; if `node.name` has no colon while `node.ns` is non-empty, reads past string buffer (heap OOB read). But `XML_Node::Serialize` — the only caller — has **zero production call sites** in the entire exiv2 codebase.
- `DumpNodeList`, `SerializeOneNode`, `CollectNamespaceDecls` are all mutually/self-recursive with no depth limit, reachable only via `XML_Node::Serialize`/`XML_Node::Dump` — again **no production call sites**.
- `kNodeKinds[node->kind]` (line 205): unchecked index, only reached via `XML_Node::Dump` — also not in production path.

**ParseRDF.cpp call chain analysis (processes XML_Node trees):**
- `ProcessRDF` → `RDF_RDF` → `RDF_NodeElementList` → `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` (line 987) → back to `RDF_NodeElement`: **no depth counter, no limit**.
- This cycle is 4–5 C stack frames per one level of XML nesting.
- Production path confirmed: `exiv2 pr <file>` → `XmpParser::decode()` → `SXMPMeta(xmpPacket, len)` → `XMPMeta::ParseFromBuffer()` → `ProcessRDF()`.
- Expat builds the XML_Node tree iteratively (event-driven callbacks, no C-stack growth per nesting level), so arbitrarily deep XML can be built, then handed to `ProcessRDF` which recurses into it.

## VULN: Unbounded Recursive Descent in RDF/XMP Parser Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement(), RDF_PropertyElementList(), RDF_PropertyElement(), RDF_ResourcePropertyElement()
- **行号**: ParseRDF.cpp:693–707 (RDF_NodeElement), ParseRDF.cpp:985–987 (RDF_ResourcePropertyElement→RDF_NodeElement back-edge), call entry via ProcessRDF:623
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file (JPEG, TIFF, PNG, WEBP, or any format supporting embedded XMP)
- **外部触发路径**: `exiv2 pr <file>` → `Image::readMetadata()` → `XmpParser::decode()` → `SXMPMeta(xmpPacket, len)` (constructor calls `XMPMeta::ParseFromBuffer()`) → `ExpatAdapter::ParseBuffer()` (builds `XML_Node` tree iteratively from XMP packet) → `ProcessRDF(&tree, *xmlRoot, options)` → `RDF_RDF()` → `RDF_NodeElementList()` → `RDF_NodeElement()` → `RDF_PropertyElementList()` → `RDF_PropertyElement()` → `RDF_ResourcePropertyElement()` (ParseRDF.cpp:987: `RDF_NodeElement(newCompound, **currChild, kNotTopLevel)`) → [recurse with no depth limit] → stack exhaustion
- **描述**: `ProcessRDF` 及其调用的函数族（`RDF_NodeElement`↔`RDF_PropertyElementList`↔`RDF_PropertyElement`↔`RDF_ResourcePropertyElement`）构成无深度限制的互递归环。每深入 XMP 的一层 struct/resource 属性嵌套，就在 C 调用栈上新增约 4–5 个栈帧（`RDF_NodeElement`、`RDF_PropertyElementList`、`RDF_PropertyElement`、`RDF_ResourcePropertyElement`）。expat XML 解析器本身以事件驱动回调方式工作，无需 C 栈递归即可构建任意深度的 `XML_Node` 树；构建完成后 `ProcessRDF` 对该树进行无限制递归遍历，导致栈空间耗尽（stack overflow），进而破坏栈帧、返回地址及保存的寄存器，理论上可被利用实现任意代码执行。
- **触发条件**: 攻击者在图像文件（如 JPEG APP1 段、TIFF IFD 的 XMP tag、PNG iTXt chunk 等）中嵌入包含深层嵌套 RDF struct 属性的 XMP 数据包。例如在 rdf:Description 中持续嵌套 `<ns:prop><rdf:Description><ns:prop><rdf:Description>...` 数千层，即可将递归调用栈推向耗尽。每层约需 4–5 个栈帧，默认 8 MB 栈在约 10,000–20,000 层嵌套时耗尽。
- **安全影响**: 最坏情况下，精确控制栈溢出的写入内容可实现 RCE（远程/本地代码执行）；一般情况下可稳定触发进程崩溃（DoS），影响所有调用 `exiv2 pr <file>` 或通过库 API 解析含恶意 XMP 图像文件的应用程序。

<!-- AUDIT_PROMPT_VERSION: 1 -->
