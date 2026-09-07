Now I have the full picture. Key confirmation:
- `addSpecialChar()` inserts `formFieldFont` (created as `new TextFontInfo()` in HTMLGen) directly into `TextPage::chars`, but **never** into `TextPage::fonts` (which is only appended via `new TextFontInfo(state)` at line 1379).
- `text->getFonts()` returns only `TextPage::fonts`—so `formFieldFont` is always absent from that list.
- Line 697 guards the special-char case, but only when `convertFormFields == true`. If through layout analysis (proximity merge, etc.) a special char ends up in a TextWord not satisfying the pointer check, the guard fails and the OOB read fires at line 803.

Summary of analysis per batch:
- **Batch 1 (1–500)**: `Base64Encoder`, bitmaps, HTML header generation — no memory-safety issues found.
- **Batch 2 (500–890)**: `fontScales` allocation at line 506, linear font search at lines 779–783, unconditional `fontScales[i]` access at line 803 — **OOB read identified** when font not in list.
- **Batch 3 (890–1191)**: `appendUTF8` (safe: all branches checked, no write overflows), `getFontFile`/`getSubstituteFont` (GString::format, safe), `genDocMetadata*` (safe GString appends), `memset` in form-field erasure (bounds properly clamped) — no additional vulnerabilities.

---

## VULN: Heap OOB Read in fontScales via Unmatched Font Pointer in appendSpans
- **漏洞类别**: memory-safety
- **函数**: HTMLGen::appendSpans()
- **行号**: 779-803
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: pdftotext → HTMLGen::convertPage() → text->getFonts() [line 505, returns TextPage::fonts list] → gmallocn(fonts->getLength(), sizeof(double)) → fontScales [line 506] → appendSpans() [line 610] → for-loop search (lines 779–783) exits with i == fonts->getLength() when font not found → fontScales[i] OOB read [lines 803, 810]
- **描述**: `fontScales` 在 `convertPage()` 第 506 行按 `fonts->getLength()` 个 `double` 分配（有效下标 0 到 N-1）。`appendSpans()` 第 779-783 行对 `fonts` 做线性指针搜索，若 `word1->getFontInfo()` 指针不在该列表中，循环以 `i == fonts->getLength()` 退出，随后第 803 / 810 行无边界检查地访问 `fontScales[i]`，造成堆越界读取 8 字节（一个 `double`）。`formFieldFont` 由 `new TextFontInfo()` 在 HTMLGen 内创建（第 429 行），通过 `text->addSpecialChar()` 写入 `TextPage::chars`，但**从未**追加到 `TextPage::fonts` 列表（后者仅在 TextOutputDev.cc 第 1379 行经 `new TextFontInfo(state)` 路径追加）。若布局算法将含 `formFieldFont` 的特殊字符合并进某个 TextWord，而该 word 的指针恰好未能通过第 697 行的 `word0->getFontInfo() == formFieldFont` 指针比较（如因布局合并、字体对象克隆等原因指针不同），则该 word 进入 `else` 分支，第 779 行搜索失败，第 803 行读取越界内存。
- **触发条件**: 构造含表单字段（AcroForm text/checkbox）的 PDF，使 `convertFormFields` 路径激活；同时构造特定页面布局使含 `formFieldFont` 的特殊字符在 TextPage 布局阶段被合并进普通 TextWord（与正常文本字符相邻，触发 TextPage 的字符合并逻辑），导致 `word->getFontInfo()` 不等于 `formFieldFont` 成员指针，越过第 697 行守卫进入 `appendSpans` 的普通分支。
- **安全影响**: 堆越界读取 8 字节（double 值被用作字体大小乘数并写入 HTML 输出），可导致程序崩溃（DoS）或通过 HTML 输出间接泄露堆内存布局信息。在自动化 PDF 处理管道（邮件附件处理、文档转换服务）中可被远程触发。

<!-- AUDIT_PROMPT_VERSION: 1 -->
