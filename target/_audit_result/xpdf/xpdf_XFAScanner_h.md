I have now completed a thorough, multi-pass analysis of `XFAScanner.h` and `XFAScanner.cc` (687 lines total), including all related helpers. Here is the final report:

## VULN: Unbounded Recursion in scanNode / scanFormNode Causes Stack Overflow
- **漏洞类别**: memory-safety
- **函数**: XFAScanner::scanNode(), XFAScanner::scanFormNode()
- **行号**: 242-329 (scanNode), 201-240 (scanFormNode)
- **CWE**: CWE-674 (Uncontrolled Recursion)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file containing deeply nested XFA XML template structure
- **外部触发路径**: pdftotext input.pdf → Catalog::readAcroForm() → XFAScanner::load() → ZxDoc::loadMem() → XFAScanner::scanNode(tmpl, …) → [recursive self-call for every child ZxElement] → stack exhaustion; scanFormValues() → scanFormNode() has the same unbounded recursion path
- **描述**: `scanNode` performs a depth-first traversal of the XFA XML element tree via direct C++ recursion — for each `ZxElement` child it unconditionally calls itself with no depth counter or limit (line 310: `scanNode((ZxElement *)child, …)`). `scanFormNode` is equally unbounded (lines 232, 235). The XFA XML document is built entirely from attacker-controlled bytes in the PDF stream (`readXFAStreams` imposes no size or nesting limit), so an arbitrarily deep element tree can be constructed. Each stack frame for `scanNode` allocates at least two `GHash` objects on the heap and several local `GString` pointers; the stack frame size itself is several hundred bytes. A nesting depth of ~10,000–50,000 (easily encoded in a small XFA packet) exhaust the default 8 MB process stack, writing past the stack guard page and corrupting adjacent memory.
- **触发条件**: Embed an XFA stream in the PDF's AcroForm `/XFA` entry whose `<template>` subtree contains thousands of recursively nested `<subform>` or `<field>` elements, e.g. `<subform><subform><subform>…</subform>…`. No password, no authentication, no special privileges required — any pdftotext invocation on such a file triggers the path.
- **安全影响**: Reliable process crash (DoS). On systems or builds that lack per-thread stack guard pages or that use split stacks, the overflow may overwrite heap metadata or return addresses adjacent to the stack, potentially enabling arbitrary code execution (RCE). At minimum this crashes the pdftotext process and any parent application that embeds it.

<!-- AUDIT_PROMPT_VERSION: 1 -->
