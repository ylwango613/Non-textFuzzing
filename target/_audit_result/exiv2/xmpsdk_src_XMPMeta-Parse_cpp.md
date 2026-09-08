I have completed my systematic 3-pass read of the 1306-line file plus investigation of the key call-chain in ParseRDF.cpp and related headers. Here is my analysis summary before the final output:

**Batch 1 (lines 1-599):**
- `PickBestRoot` (lines 109-136): No depth limit; recurses into every child node via the third for-loop (line 130). No guard against arbitrarily deep XML trees.
- `FindRootNode` (lines 149-216): `rootNode->parent` accessed at line 166 without null check — but all rdf:RDF nodes in the tree have a non-null parent, so unreachable in practice.
- `CompareAliasedSubtrees` (lines 289-316): For `outerCall=true`, qualifier-size mismatch between alias and base is not checked, so `baseNode->qualifiers[qualNum]` at line 312 can go OOB — but requires `kXMP_StrictAliasing` flag, which is **not** set by default in exiv2.

**Batch 2 (lines 600-1047):** `ProcessUTF8Portion` — `kReplaceLatin1[*spanEnd - 0x80]` is always in range [0,127] (128-entry table); other logic is safe.

**Batch 3 (lines 1048-1306):** `ParseFromBuffer` — always passes `last=true` to `ParseBuffer` at line 1070 regardless of the `last` parameter; correctness bug for multi-buffer callers, no memory corruption.

**ParseRDF.cpp (called from `ProcessRDF` at line 1270):** Confirmed mutual recursion `RDF_NodeElement` ↔ `RDF_PropertyElementList` ↔ `RDF_PropertyElement` ↔ `RDF_ResourcePropertyElement` ↔ `RDF_NodeElement` (line 987), and separately via `RDF_ParseTypeResourcePropertyElement` ↔ `RDF_PropertyElementList` (line 1107). No depth limit exists.

---

## VULN: XMP Stack Overflow via Unbounded PickBestRoot Recursion
- **漏洞类别**: memory-safety
- **函数**: PickBestRoot()
- **行号**: 109-136 (recursive call at line 130; dispatched from FindRootNode() at line 153)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file (XMP packet embedded in JPEG/PNG/EPS/WEBP)
- **外部触发路径**: exiv2 pr \<file\> → JpegImage::readMetadata() → XmpParser::decode() → SXMPMeta constructor → XMPMeta::ParseFromBuffer() → FindRootNode() → PickBestRoot()
- **描述**: `PickBestRoot` 递归搜索整棵 XML 节点树以定位 `x:xmpmeta` 或 `rdf:RDF` 根节点。第三个 for 循环（line 130）对当前节点的**所有**子节点无条件递归，没有任何深度计数器或终止保护。当 `xmlParser.rootCount > 1`（即 XMP 文档含多个 `rdf:RDF` 元素），且 XML 树嵌套深度为 N，则 `PickBestRoot` 形成深度 N 的调用栈。Expat 解析器使用事件回调方式构建内存中的 XML 树，自身不递归；故攻击者可将 XML 树构建到数万层深，而 `PickBestRoot` 在遍历时耗尽进程栈空间，造成栈破坏并崩溃（SIGSEGV）。
- **触发条件**: 在嵌入 XMP 的图像（JPEG/PNG 等）中构造包含至少 2 个 `<rdf:RDF>` 元素（令 `rootCount > 1`）并带有数万层深嵌套 XML 元素的 XMP 数据包。典型载体：JPEG `APP1` 段中的 XMP 包，或 PNG `iTXt`/`tEXt` 块中的 XMP 包。
- **安全影响**: 进程栈溢出导致崩溃（DoS）；在无栈保护（stack canary）的构建配置下，攻击者可能控制覆盖的返回地址，进一步达成任意代码执行（RCE）。

## VULN: XMP Stack Overflow via Unbounded Mutual Recursion in RDF Node Processing
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement() / RDF_PropertyElementList() / RDF_ResourcePropertyElement() / RDF_ParseTypeResourcePropertyElement()
- **行号**: ParseRDF.cpp:987 (RDF_ResourcePropertyElement → RDF_NodeElement), ParseRDF.cpp:1107 (RDF_ParseTypeResourcePropertyElement → RDF_PropertyElementList); 入口 XMPMeta-Parse.cpp:1270 (ProcessRDF 调用)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file (XMP packet embedded in JPEG/PNG/EPS/WEBP)
- **外部触发路径**: exiv2 pr \<file\> → JpegImage::readMetadata() → XmpParser::decode() → SXMPMeta constructor → XMPMeta::ParseFromBuffer() → ProcessRDF() → RDF_NodeElementList() → RDF_NodeElement() → RDF_PropertyElementList() → RDF_PropertyElement() → RDF_ResourcePropertyElement() → RDF_NodeElement() [循环] / 或 RDF_PropertyElement() → RDF_ParseTypeResourcePropertyElement() → RDF_PropertyElementList() [循环]
- **描述**: XMP RDF 解析器中存在两条无限互递归路径，均无深度限制：路径 A：`RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` (ParseRDF.cpp:987) → `RDF_NodeElement`（循环）。路径 B：`RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ParseTypeResourcePropertyElement` (ParseRDF.cpp:1107) → `RDF_PropertyElementList`（循环）。Expat 以事件驱动方式构建 XML/RDF 内存树，不限制嵌套深度；随后应用层以递归方式遍历该树，导致调用栈随嵌套深度线性增长，耗尽进程栈空间造成栈破坏并崩溃。
- **触发条件**: 在图像中嵌入包含数万层深嵌套 RDF 结构的 XMP 数据包：路径 A 使用深层嵌套的 `<rdf:Description>` 元素；路径 B 使用深层嵌套的 `rdf:parseType="Resource"` 属性（无需 `rootCount > 1`，任意 XMP 均可触发）。该路径不需要任何特殊解析选项，exiv2 默认处理路径即可触发。
- **安全影响**: 进程栈溢出导致崩溃（DoS）；在无栈保护（stack canary）的构建配置下，攻击者可能控制覆盖的返回地址，进一步达成任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
