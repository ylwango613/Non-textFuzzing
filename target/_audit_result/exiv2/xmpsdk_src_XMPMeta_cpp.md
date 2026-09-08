Now I have all the information I need. Let me compile the final findings from the complete code analysis.

**Batch 1 (XMPMeta.cpp lines 266-358):** `DumpPropertyTree` recurses on both `qualifiers` and `children` with no depth guard (lines 330, 350).

**Batch 2 (XMPMeta.cpp lines 549-580):** `SortWithinOffspring` recurses on `qualifiers` and `children` with no depth guard (lines 559, 574).

**Batch 3 (XMPMeta-Parse.cpp / ParseRDF.cpp):** `ParseFromBuffer` → `ProcessRDF` → `RDF_NodeElementList` → `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_ResourcePropertyElement` → `RDF_NodeElement` — this mutual recursion has no depth limit.

**Expat adapter confirmed:** The `StartElementHandler`/`EndElementHandler` build the XML tree iteratively via a `parseStack` vector (heap-based), so expat-level parsing does NOT limit nesting depth — it produces an arbitrarily deep XML_Node tree. After that, the above recursive functions traverse it using the C call stack.

**No other memory-safety bugs** (integer overflow, OOB array access, UAF, etc.) were found in XMPMeta.cpp after full review of all functions. The `kReplaceLatin1[128]` table access is bounded, `DumpNodeOptions` array access is bounded (32 elements, 32-bit mask), `pendingInput` memcpy calls are bounded by `kXMLPendingInputMax=16`.

## VULN: Unbounded Mutual Recursion in XMP RDF Parser Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: RDF_NodeElement() / RDF_PropertyElementList() / RDF_ResourcePropertyElement() — called from XMPMeta::ParseFromBuffer()
- **行号**: ParseRDF.cpp:693-707 / 785-798 / 941-998; XMPMeta-Parse.cpp:1270
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file with deeply nested XMP/RDF XML
- **外部触发路径**: exiv2 pr/pa \<file\> → Exiv2::XmpParser::decode() → XMPMeta::ParseFromBuffer() → ProcessRDF() → RDF_RDF() → RDF_NodeElementList() → RDF_NodeElement() → RDF_PropertyElementList() → [propertyElt handler] → RDF_ResourcePropertyElement() → RDF_NodeElement() → … (unbounded mutual recursion)
- **描述**: `RDF_NodeElement` calls `RDF_PropertyElementList`, which dispatches to `RDF_ResourcePropertyElement` for compound property elements, which in turn calls `RDF_NodeElement` again. This mutual recursion has no depth counter or guard. The expat adapter builds the XML_Node tree iteratively (via a heap `parseStack`), so an arbitrarily deep XML tree is created without triggering any expat-level limit. The subsequent recursive-descent RDF recognizer then consumes C stack linearly with the XML nesting depth. Crafting ~15 000 nested `rdf:Description` elements (each wrapping a struct property) exhausts the default 8 MB stack.
- **触发条件**: 攻击者在 XMP 包中嵌入深度嵌套的 `rdf:Description`/struct 属性链（约 15 000 层），并将此 XMP 写入任意图像格式（JPEG APP1、PNG 的 iTXt 块、TIFF 标签 700 等）。exiv2 解析该图像时，在 `ParseFromBuffer` 调用链中即触发。
- **安全影响**: 栈耗尽导致进程崩溃（DoS）。在未部署栈金丝雀的旧工具链下，或在线程栈较小的服务进程中，理论上可进一步演变为返回地址覆写从而导致 RCE。

## VULN: Unbounded Recursion in DumpPropertyTree Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: DumpPropertyTree()
- **行号**: XMPMeta.cpp:266-358 (recursive calls at lines 330 and 350)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file with deeply nested XMP property tree
- **外部触发路径**: exiv2 pr \<file\> → Exiv2::XmpParser::decode() → XMPMeta::ParseFromBuffer() [builds deep XMP tree] → XMPMeta::DumpObject() → DumpPropertyTree(schema) → DumpPropertyTree(child, indent+1) → DumpPropertyTree(grandchild, indent+2) → … (unbounded)
- **描述**: `DumpPropertyTree` 对每个节点的 `qualifiers`（第330行）和 `children`（第350行）分别进行递归调用，没有任何深度计数或截止条件。当 XMP 元数据树深度达到数千级（由 RDF 解析器从外部输入构造）时，每次递归调用消耗一个 C 栈帧（局部变量 + 返回地址 ~120 字节），导致栈耗尽。
- **触发条件**: 攻击者构造深度嵌套的 XMP struct 属性链（如 `ns:a/ns:b/ns:c/…`），嵌入图像文件。当 exiv2 对该文件执行打印操作（内部调用 `DumpObject()`）时触发。所需嵌套深度约 60 000+ 层（每帧 ~120B，默认栈 8MB）。
- **安全影响**: 进程崩溃（DoS）。在线程池中运行的服务端图像处理场景下，单一恶意文件即可造成工作线程崩溃。

## VULN: Unbounded Recursion in SortWithinOffspring Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: SortWithinOffspring()
- **行号**: XMPMeta.cpp:549-580 (recursive calls at lines 559 and 574)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file with deeply nested XMP property tree
- **外部触发路径**: exiv2 \<file\> → Exiv2::XmpParser::decode() → XMPMeta::ParseFromBuffer() [builds deep XMP tree] → XMPMeta::Sort() → SortWithinOffspring(tree.children) → SortWithinOffspring(child.qualifiers or child.children) → SortWithinOffspring(…) → … (unbounded)
- **描述**: `SortWithinOffspring` 对节点向量中每个节点的 `qualifiers`（第559行）和 `children`（第574行）进行无深度限制的递归调用。XMP 树的深度由外部解析的 XMP 数据决定，攻击者可通过构造深度嵌套的 XMP struct 属性使树深度达到任意值，进而在调用 `Sort()` 时耗尽 C 调用栈。
- **触发条件**: 攻击者构造包含深度嵌套 XMP struct 的图像文件。exiv2 解析后调用 `Sort()`（exiv2 在序列化前会对 XMP 数据排序）时触发。所需嵌套深度约 40 000–60 000 层（每帧约 130–200B，默认栈 8MB）。
- **安全影响**: 进程崩溃（DoS）；在使用 exiv2 作为库的 web 应用（图像上传处理）场景中，攻击者可通过上传一个畸形图像文件远程触发服务崩溃。

<!-- AUDIT_PROMPT_VERSION: 1 -->
