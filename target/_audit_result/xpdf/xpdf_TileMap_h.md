I now have a complete picture. Let me compile the findings.

**Analysis Summary:**

**Group 1 — `getPageBoxWidth`/`getPageBoxHeight` (TileMap.cc:1210–1216)**
Zero bounds checking. `getDPI()` at line 1202 guards with `if (page < 1 || page > numPages)`, but these two accessor functions do not. Any call with `page ≤ 0` or `page > nPages` produces `pageBoxW[page-1]` OOB read.

**Group 2 — `getPageTopY`/`getPageBottomY`/`getPageLeftX` (TileMap.cc:929–1018)**
Checks `!doc || !numPages` but NOT `page < 1 || page > numPages`. In `displayContinuous`/`displaySideBySideContinuous` modes, directly indexes `pageY[page-1]`, `pageH[page-1]`, `pageW[page-1]`.

**Group 3 — Developer-acknowledged unguarded callers in PDFCore.cc**
PDFCore.cc:719 has explicit comment: *"NB: topPage can be out of bounds here, because the scroll position isn't adjusted until finishUpdate is called"* — that one site guards. But PDFCore.cc:550, 557, 757, 762, 766–767, 804–807 call TileMap array functions with unvalidated `getFirstPage()`/`getLastPage()` return values.

When `getFirstPage()` returns 0: `getPageTopY(0)` → `pageY[-1]`, `getPageLeftX(0)` → `pageW[-1]` — negative-index heap OOB reads on `int*` arrays allocated by `gmallocn`.

Attack path: xpdf opens a crafted PDF → PDF-triggered zoom/navigate action during transitional scroll state (e.g., `setZoom()` at PDFCore.cc:804) → `getFirstPage()` returns 0 → OOB read.

---

## VULN: Heap OOB Read in TileMap Page Accessors via Missing Bounds Check (getFirstPage returns 0)
- **漏洞类别**: memory-safety
- **函数**: TileMap::getPageTopY(), TileMap::getPageLeftX(), TileMap::getPageBottomY(), TileMap::getPageBoxWidth(), TileMap::getPageBoxHeight()
- **行号**: 929-966 (getPageTopY/getPageBottomY), 968-1018 (getPageLeftX), 1210-1216 (getPageBoxWidth/getPageBoxHeight)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file opened in xpdf GUI
- **外部触发路径**: user opens crafted PDF in xpdf → PDF link/action triggers zoom or page navigation → PDFCore::setZoom() / PDFCore::gotoPrevPage() / PDFCore::scrollToTopEdge() calls tileMap->getFirstPage() (acknowledged out-of-bounds per developer comment at PDFCore.cc:719) → returns 0 during transitional scroll state → getPageTopY(0) accesses pageY[0-1]=pageY[-1] / getPageLeftX(0) accesses pageW[-1] / getPageBoxWidth(0) accesses pageBoxW[-1] — all negative-index reads on heap-allocated arrays
- **描述**: The page accessor functions `getPageTopY`, `getPageLeftX`, `getPageBottomY`, `getPageBoxWidth`, and `getPageBoxHeight` in TileMap.cc perform no bounds validation on the `page` parameter before indexing heap arrays as `pageY[page-1]`, `pageW[page-1]`, `pageBoxW[page-1]` etc. In contrast, the analogous function `getDPI()` (line 1202) explicitly checks `page < 1 || page > numPages`. Multiple callers in PDFCore.cc (lines 550, 557, 757, 762, 766–767, 804–807) pass `tileMap->getFirstPage()` directly as `page` without guarding; a developer comment at PDFCore.cc:719 explicitly acknowledges that `getFirstPage()` can return an out-of-bounds value when the scroll position has not yet been adjusted. When `page == 0`, the expression `page - 1 == -1` causes a negative-index heap read, reading memory preceding the gmallocn-allocated array; when `page > nPages`, reads past the end of the array.
- **触发条件**: 攻击者构造 PDF，其中包含跳转链接（GoTo Action）或缩放触发操作，使 xpdf 在 `startUpdate`/`finishUpdate` 周期的过渡时段（滚动位置尚未调整时）调用 `setZoom()` 或 `gotoPrevPage()`；此时 `getFirstPage()` 返回 0，进而传入无边界检查的 TileMap 访问器函数。
- **安全影响**: 堆越界读（pageY[-1]、pageW[-1]、pageBoxW[-1]）——最轻后果为崩溃（DoS）；若 gmallocn 堆布局可预测，相邻堆内存（如字体数据、PDF 对象缓冲区）可被泄露（信息泄露）；在罕见场景下与其他漏洞链式利用可辅助 RCE。

<!-- AUDIT_PROMPT_VERSION: 1 -->
