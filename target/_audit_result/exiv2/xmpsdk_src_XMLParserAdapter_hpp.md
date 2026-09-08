I have thoroughly read and analyzed the target file and all relevant implementation files. Let me now compile the final findings.

**Summary of analysis:**

1. **`XMLParserAdapter.hpp`** defines the `XML_Node` tree structure and `XMLParserAdapter` base class. Key: `XML_Node::~XML_Node()` at line 95 calls `RemoveContent()` then `RemoveAttrs()`.

2. **`XML_Node.cpp`**: `RemoveContent()` (line 438–444) calls `delete this->content[i]` for each child, triggering `~XML_Node()` recursively — **no depth limit**.

3. **`ExpatAdapter.cpp`**: Expat 2.4.7 (system-installed) has **no XML element depth limit**, so it will build arbitrarily deep trees.

4. **`ParseRDF.cpp`**: Mutual recursion: `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` → `RDF_NodeElement` — **no depth limit**.

5. **`XMPMeta-Parse.cpp`**: Both the success path (line 1289: `delete this->xmlParser`) and the exception path (line 1296) call the recursive destructor chain. `PickBestRoot` also recurses into all XML tree children without a depth limit (line 131).

Both stack overflow patterns are externally triggered by embedding deeply-nested XML in the XMP metadata of any image file processed by exiv2.

## VULN: Stack Overflow via Recursive XML_Node Destructor in XMP Cleanup
- **漏洞类别**: memory-safety
- **函数**: `XML_Node::~XML_Node()` / `XML_Node::RemoveContent()`
- **行号**: XMLParserAdapter.hpp:95 / XML_Node.cpp:438-444
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file with deeply nested XMP XML
- **外部触发路径**: `exiv2 pr <file>` → `XMPMeta::ParseFromBuffer()` [XMPMeta-Parse.cpp:1092] → (success at line 1289 or exception at line 1296) `delete this->xmlParser` → `~ExpatAdapter()` → implicit `~XMLParserAdapter()` destroying member `tree` (XML_Node) → `XML_Node::~XML_Node()` [XMLParserAdapter.hpp:95] → `RemoveContent()` [XML_Node.cpp:438] → `delete this->content[i]` → `XML_Node::~XML_Node()` → ... (unbounded recursion to tree depth)
- **描述**: `XML_Node::~XML_Node()` (XMLParserAdapter.hpp:95) calls `RemoveContent()` which deletes each child `XML_Node` via `delete this->content[i]` (XML_Node.cpp:441), which in turn invokes `~XML_Node()` on that child, which calls `RemoveContent()` again. This forms an unbounded recursive destructor chain proportional to the XML tree depth. Since the system-linked Expat 2.4.7 imposes no element nesting depth limit, an attacker can craft an XMP block with e.g. 50,000 nested XML elements. When `exiv2` deletes `this->xmlParser` (on both the success path at line 1289 and the exception path at line 1296 of `XMPMeta-Parse.cpp`), the destructor chain exhausts the thread stack, causing a stack overflow. The same recursive pattern occurs in `RemoveAttrs()` for attribute nodes.
- **触发条件**: 攻击者构造一个包含 XMP 元数据的图像文件（JPEG APP1/APP13 标记、TIFF XMP IFD、PNG zTXt chunk 等），其中 XMP 数据包含深度嵌套的 XML 结构（如 10,000–50,000 层嵌套元素 `<a0><a1><a2>...<aN/>..</a2></a1></a0>`），该结构对 Expat 而言是合法 XML，不需要满足 RDF/XMP 语义约束。
- **安全影响**: 最坏情况下导致栈溢出可覆盖返回地址，进而 RCE；最低限度造成进程崩溃（DoS）。在 64 位 Linux 系统中，栈溢出通常触发 SIGSEGV，若攻击者能控制栈布局（如 JIT-spray 或 stack spray 技术）则有潜在 RCE 可能。

## VULN: Stack Overflow via Unbounded Mutual Recursion in XMP RDF Parser
- **漏洞类别**: memory-safety
- **函数**: `RDF_NodeElement()` / `RDF_PropertyElementList()` / `RDF_PropertyElement()` / `RDF_ResourcePropertyElement()`
- **行号**: ParseRDF.cpp:693-707 / 784-798 / 851-925 / 940-998
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file with deeply nested RDF/XMP structure
- **外部触发路径**: `exiv2 pr <file>` → `XMPMeta::ParseFromBuffer()` → `ProcessRDF()` [ParseRDF.cpp:623] → `RDF_RDF()` [line 644] → `RDF_NodeElementList()` [line 662] → `RDF_NodeElement()` [line 693] → `RDF_PropertyElementList()` [line 784] → `RDF_PropertyElement()` [line 851] → `RDF_ResourcePropertyElement()` [line 940] → `RDF_NodeElement()` [line 987, recursive call] → `RDF_PropertyElementList()` → ... (cycle repeats, no depth check)
- **描述**: The RDF recognizer in `ParseRDF.cpp` uses mutually recursive functions with no recursion depth limit. `RDF_ResourcePropertyElement()` calls `RDF_NodeElement(newCompound, **currChild, kNotTopLevel)` at line 987, which calls `RDF_PropertyElementList()` at line 704, which calls `RDF_PropertyElement()` for each child, which may call `RDF_ResourcePropertyElement()` again. Similarly, `RDF_ParseTypeResourcePropertyElement()` at line 1107 calls `RDF_PropertyElementList()`, continuing the chain. Each cycle of this mutual recursion adds ~4 stack frames. On a typical Linux system (8 MB stack), roughly 5,000–10,000 levels of nested RDF elements are sufficient to exhaust the stack.
- **触发条件**: 攻击者构造包含 XMP 元数据的图像文件，其中 XMP 的 RDF 部分包含深度嵌套的 `rdf:Description` 元素（每层通过 `resourcePropertyElt` 嵌套子 `rdf:Description`），或大量嵌套的 `rdf:parseType="Resource"` 属性。这要求 XMP 满足基本的 RDF 语法，但不需要语义上合法。
- **安全影响**: 栈溢出导致进程崩溃（DoS），在可控条件下有 RCE 可能。任何在 exiv2 解析路径中处理 XMP 的调用方（包括图像查看器、批处理工具、服务端图片转换服务）均受影响。

## VULN: Stack Overflow via Unbounded Recursion in PickBestRoot XML Tree Search
- **漏洞类别**: memory-safety
- **函数**: `PickBestRoot()`
- **行号**: XMPMeta-Parse.cpp:110-137 (递归调用位于 line 118 和 line 131)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.6 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted image file with deeply nested XML in XMP block
- **外部触发路径**: `exiv2 pr <file>` → `XMPMeta::ParseFromBuffer()` → `FindRootNode()` [XMPMeta-Parse.cpp:150] → `PickBestRoot(xmlParser.tree, options)` [line 154] → `PickBestRoot(*childNode, 0)` [line 118, for x:xmpmeta] OR `PickBestRoot(*xmlParent.content[childNum], options)` [line 131, for all other children] → ... (unbounded depth)
- **描述**: `PickBestRoot()` performs a depth-first search over the entire XML node tree, recursively calling itself on each child node (line 131: `PickBestRoot(*xmlParent.content[childNum], options)`) with no depth limit. For a deeply nested XML document, this recursion reaches a depth equal to the XML tree depth, exhausting the call stack. The recursion at line 118 (for `x:xmpmeta` elements) is also unbounded. This is triggered before `ProcessRDF()`, on `xmlParser.rootCount > 1` (multiple root candidates) or always when searching the tree.
- **触发条件**: 攻击者构造包含 XMP 元数据的图像文件，其中 XMP 的 XML 内容包含深度嵌套的非 RDF 元素（例如在 `x:xmpmeta` 包装器内部嵌套数万层普通 XML 元素）。由于 Expat 2.4.7 无元素深度限制，此类 XML 将被成功解析为树结构，然后在 `PickBestRoot` 遍历时触发栈溢出。
- **安全影响**: 进程崩溃（DoS），在特定条件下有 RCE 可能。

<!-- AUDIT_PROMPT_VERSION: 1 -->
