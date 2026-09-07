**Analysis complete.** Full summary before final report:

- **Batch 1 (1-500)**: Static tables, `AcroForm::load()`. `touchedObjs` allocation is safe.
- **Batch 2 (500-1000)**: `scanField`, `getFont()`. **Found: OOB read at lines 1013-1016** — when "Tm" appears before "Tf" in the DA string and "Tf" is the last token, `daToks->get(tfPos + 3)` exceeds `daToks->length`. GList::expand() uses `realloc` (no zero-init) → slot 10+ is uninitialized garbage → `->getCString()` dereferences garbage → crash.
- **Batch 3 (1000-1500)**: `drawAnnot`, `drawNewAppearance`. Border dash array allocations use `gmallocn` (safe). `drawExistingAppearance` clean.
- **Batch 4 (1500-2000)**: `drawText` setup. `tmPos+4` / `tmPos+5` access = `i-2` / `i-1`, always within bounds (unlike `getFont`). Clean.
- **Batch 5 (2000-2500)**: Multi-line text, comb formatting. `daToks->get(tfPos+1)` valid. No OOB.
- **Batch 6 (2500-2985)**: `drawListBox` rendering. `tmPos+4`/`tmPos+5` same safe pattern. Barcode tables correctly bounds-checked: code3Of9Data[c&0x7f] (0-127), code128Data[c] (0-106 max). Clean.
- **Batch 7 (2985-3500)**: `tokenize`, `getAnnotResources`, `buildDefaultResourceDict`, `fieldLookup`, `utf8ToUnicode`, picture parsing. No OOB.
- **Batch 8 (3500-3927)**: `pictureFormatNumber` digit indexing, `pictureFormatText`, `isValidInt`, `convertInt`. Clean.

**Root cause confirmed**: In `getFont()`, the comment says "handle the Tm operator" but the code reads `tfPos + 2` and `tfPos + 3` instead of `tmPos + 2` and `tmPos + 3`. When "Tm" precedes "Tf" in a DA string with "Tf" as the last token (e.g., `1 0 0 1 10 20 Tm /F1 12 Tf` = 10 tokens), `tfPos = 7`, `tfPos + 3 = 10 = list.length` → OOB into uninitialized heap memory → bad pointer dereference.

---

## VULN: Out-of-Bounds Read in AcroFormField::getFont() via Crafted DA String with Tm Before Tf
- **漏洞类别**: memory-safety
- **函数**: AcroFormField::getFont()
- **行号**: 1013-1017
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: `pdftohtml input.pdf outdir/` → `HTMLGen::scan*()` (HTMLGen.cc:712) → `AcroFormField::getFont()` → `tokenize(da)` → `GList::get(tfPos + 3)` OOB
- **描述**: `getFont()` 在处理 "Tm" 操作符时，错误地使用 `tfPos + 2` / `tfPos + 3` 访问 token 列表（注释说是 Tm 的 m[2]/m[3]，实际应为 `tmPos + 2` / `tmPos + 3`）。当 DA 字符串中 "Tm" 出现在 "Tf" 之前（如 `1 0 0 1 100 200 Tm /F1 12 Tf`，共 10 个 token），"Tf" 在 index 9（最后一个元素），则 `tfPos = 7`，`tfPos + 3 = 10 = daToks->getLength()`，超出 `GList::data[]` 的有效范围。GList 通过 `realloc` 扩容（初始 size=8，扩展为 16 时不零初始化），`data[10]` 是未初始化的堆内存，被强制转换为 `GString*` 后调用 `->getCString()`，触发对无效指针的解引用，导致崩溃（SIGSEGV）。
- **触发条件**: 在 PDF AcroForm 字段的 DA（Default Appearance）字符串中，将 "Tm" 操作符放在 "Tf" 操作符之前，且 "Tf" 为该字符串的最后一个操作符（如 `/AcroForm << /Fields [...] /DA (1 0 0 1 100 200 Tm /F1 12 Tf) >>`）。使用 `pdftohtml` 处理此 PDF 时触发 `getFont()`。
- **安全影响**: 最坏情况为可靠崩溃（DoS）；若攻击者能控制堆布局，`data[10]` 处的未初始化内存可能包含来自其他 PDF 对象的残留指针，存在堆信息泄露风险；在 PDF 文档批量处理（邮件网关、服务器端文档转换）场景下，可造成服务中断。

<!-- AUDIT_PROMPT_VERSION: 1 -->
