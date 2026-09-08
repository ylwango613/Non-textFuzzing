I now have a complete understanding of the file and its call chain. Let me write the final report.

Based on my full read of `ExpatAdapter.cpp` and systematic exploration of the call chain through `XMLParserAdapter.hpp`, `ExpatAdapter.hpp`, `XMPMeta-Parse.cpp`, and `ParseRDF.cpp`, here is the complete analysis:

**Key observations:**

1. `ExpatAdapter::ExpatAdapter()` (line 84) creates an Expat parser with `XML_ParserCreateNS` but sets **no element nesting depth limit** — no call to any depth-capping API.

2. `StartElementHandler` (line 334) unconditionally calls `thiz->parseStack.push_back(elemNode)` for every XML element, allowing the in-memory XML tree to grow to unlimited depth (heap-based, no stack overflow at this stage).

3. `ExpatAdapter::ParseBuffer()` (line 125) passes `size_t length` directly to `XML_Parse()` which takes `int len` — implicit narrowing conversion, but XMP packets are small in practice so not exploitable.

4. After Expat finishes, `XMPMeta::ParseFromBuffer()` (XMPMeta-Parse.cpp:1270) calls `ProcessRDF()` which triggers a **mutual recursion** in `ParseRDF.cpp` with no depth limit: `RDF_NodeElement → RDF_PropertyElementList → RDF_PropertyElement → RDF_ResourcePropertyElement → RDF_NodeElement`. This recursion, driven by the arbitrarily deep XML tree built by `ExpatAdapter`, causes stack overflow.

5. `SetQualName` (line 198) has a `size_t` underflow when `strlen(fullName)==0` but Expat guarantees non-empty element names, so not externally triggerable.

## VULN: Stack Overflow via Unbounded Recursive RDF Processing of Deep XMP XML Tree
- **漏洞类别**: memory-safety
- **函数**: ExpatAdapter::ExpatAdapter() / ExpatAdapter::ParseBuffer() → ProcessRDF() → RDF_NodeElement() → RDF_ResourcePropertyElement() (mutual recursion)
- **行号**: ExpatAdapter.cpp:84 (no depth limit set), ExpatAdapter.cpp:125-170 (ParseBuffer feeds unlimited-depth tree), ParseRDF.cpp:940-998 (RDF_ResourcePropertyElement→RDF_NodeElement recursive loop)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file containing a deeply nested XMP packet
- **外部触发路径**: `exiv2 pr <file>` → `Image::readMetadata()` → `XmpParser::decode()` → `SXMPMeta::ParseFromBuffer()` → `XMP_NewExpatAdapter()` + `ExpatAdapter::ParseBuffer()` → `XML_Parse()` (Expat, no depth cap) → `StartElementHandler()` builds N-level-deep XML tree → `ProcessRDF()` → `RDF_RDF()` → `RDF_NodeElementList()` → `RDF_NodeElement()` → `RDF_PropertyElementList()` → `RDF_PropertyElement()` → `RDF_ResourcePropertyElement()` → `RDF_NodeElement()` [recursive, no depth guard, N cycles deep → stack exhaustion]
- **描述**: `ExpatAdapter::ExpatAdapter()` creates the Expat parser without calling any nesting-depth-limiting API (e.g., no `XML_SetMaxElementDepth`). Consequently, `StartElementHandler` pushes one heap node per XML element with no bound, allowing the in-memory XML tree to grow arbitrarily deep. After `ExpatAdapter::ParseBuffer()` returns, `ProcessRDF()` processes the tree via mutual C++ recursion in `ParseRDF.cpp`: `RDF_NodeElement` → `RDF_PropertyElementList` → `RDF_PropertyElement` → `RDF_ResourcePropertyElement` → `RDF_NodeElement` (repeat). There is no recursion depth counter or guard anywhere in this chain. Each nesting level consumes approximately 5 stack frames; with tens of thousands of levels of XML nesting the call stack is exhausted, overwriting the stack guard page and crashing the process (SIGSEGV). On systems without stack canaries or with exploitable stack layout, further exploitation towards RCE may be possible.
- **触发条件**: Embed an XMP packet in a JPEG, TIFF, or PNG file whose RDF/XML content has thousands of nested property elements (e.g., repeated `<rdf:Description><dc:prop><rdf:Description><dc:prop>...`) to depth ≥ ~2000 levels (exact threshold depends on per-frame stack usage). The file must pass Expat's well-formedness checks (valid UTF-8, balanced tags), which it trivially can.
- **安全影响**: Deterministic crash (DoS) of any process invoking exiv2 or the libexiv2 library on the crafted file. If the stack overflow overwrites a return address before the guard page triggers, or if ASLR+stack-canaries are absent, this escalates to arbitrary code execution (RCE) under the privileges of the parsing process. Services that accept user-uploaded images and call exiv2/libexiv2 for metadata extraction are exposed remotely with no authentication required.

<!-- AUDIT_PROMPT_VERSION: 1 -->
