Full read complete. I've now analyzed all 2650 lines across 5 batches.

**Key findings per batch:**

- **Lines 1–500**: Font type detection, readFontDescriptor — no issues; all array accesses bounded.
- **Lines 501–950**: `readEmbFontFile` — doubling buffer with `INT_MAX/2` guard; safe.
- **Lines 951–1500**: `Gfx8BitFont` constructor encoding/widths — `firstChar`/`lastChar` clamped to [0,255]; safe.
- **Lines 1501–2050**: CIDToGIDMap read loop (capacity doubling, `greallocn` catches negative `i`). W-array width expansion — `greallocn` overflow checks prevent silent heap overflow. **Found: `parensAreSwapped()` uses `i <= cidToGIDLen` (line 2351) instead of `i < cidToGIDLen`, reading one `int` past the valid cidToGID array.**
- **Lines 2051–2650**: Confirmed the `readTrueTypeUnicodeMapping` uses correct `i < cidToGIDLen` (line 2132) — only `parensAreSwapped` has the off-by-one.

## VULN: Off-by-one OOB heap read in GfxCIDFont::parensAreSwapped() via cidToGID array
- **漏洞类别**: memory-safety
- **函数**: GfxCIDFont::parensAreSwapped()
- **行号**: 2350-2357
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 3.7 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Low
- **攻击向量**: crafted PDF file
- **外部触发路径**: pdftotext main() → PDFDoc::displayPage() → Gfx::display() → GfxFont::makeFont() → GfxCIDFont::GfxCIDFont() [读取CIDToGIDMap流填充 cidToGID] → … → GfxCIDFont::parensAreSwapped(xref) [循环条件用 `i <= cidToGIDLen` 导致OOB读]
- **描述**: 在 `GfxCIDFont::parensAreSwapped()` 的循环（line 2351）中，终止条件写作 `i <= cidToGIDLen` 而非 `i < cidToGIDLen`。`cidToGID` 数组由 `GfxCIDFont` 构造函数通过倍增策略从流中填充，容量（`cap`）始终满足 `cap >= cidToGIDLen`，故当 `i == cidToGIDLen` 时访问 `cidToGID[cidToGIDLen]` 落在已分配堆块内但超出有效数据，读取未初始化或脏堆内存（CWE-125 heap OOB read）。相比之下，同文件 line 2132 的 `readTrueTypeUnicodeMapping()` 对同一数组用了正确的 `i < cidToGIDLen`，证实这是一个孤立的笔误。
- **触发条件**: 攻击者构造的 PDF 文件包含：(1) Type 0 CID 字体，其后裔为 CIDFontType2（TrueType）；(2) FontDescriptor 中 FontFile2 指向的嵌入 TrueType 字体流；(3) 字体字典中存在 `CIDToGIDMap` 流（使 `cidToGID != NULL`）；(4) 存在 `ToUnicode` CMap（`hasToUnicode = true`）；(5) 字符集合非已知 AdobeCJK 集（`hasKnownCollection = false`）。满足上述条件时，`parensAreSwapped()` 被调用，循环读取 `cidToGID[cidToGIDLen]`（堆内越界一个 `int` 单元）。
- **安全影响**: 读取一个未初始化堆 `int` 值并与嵌入字体中 `(` / `)` 字符的 GID 比较。若该脏值碰巧与某 GID 匹配，会错误设置 `leftParenCID` 或 `rightParenCID`，但 `CharCodeToUnicode::mapToUnicode()` 中的 `c >= mapLen` 守卫阻止进一步越界；实际后果为函数返回错误的 `swapped` 布尔值，导致括号映射逻辑错误（信息输出差异）。本身无法直接用于 RCE，但属于可被内存安全工具（ASAN/Valgrind）检出的真实堆越界读，在特殊堆布局下存在泄露其他堆对象内容的理论可能（信息泄露 DoS 辅助原语）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
