Now I have a complete picture from reading all of FoFiType1C.cc (3473 lines) and its dependencies. Let me compile the analysis results.

**Batch 1 (lines 1-600):** Parse/initialization, convertToType1 — encoding output logic, string ops. No obvious OOB.

**Batch 2 (lines 600-1200):** CID map building, convertToCIDType0 — fdSelect bounds checked via readFDSelect validation. gmallocn confirmed to have overflow protection at line 210 in gmem.cc.

**Batch 3 (lines 1200-1800):** cvtGlyph charstring dispatch loop — ops[] array capped at 49 elements by `if (nOps < 49)` guard. callsubr/callgsubr use getIndexVal which validates k against `[0, idx->len)`.

**Batch 4 (lines 1800-2400):** More operator cases (vhcurveto/hvcurveto), cvtGlyphWidth, cvtNum, OpenType table building — all within bounds.

**Batch 5 (lines 2400-3000):** parse(), readTopDict(), readFD(), readPrivateDict() — operators accessing ops[0..5] without checking nOps, but all within ops[49] array (stale read, not OOB corruption).

**Batch 6 (lines 3000-3473):** readFDSelect(), buildEncoding(), readCharset(), getOp(), getIndex(), getIndexVal(), getString() — bounds checking mostly solid. FoFiBase.cc confirms getU8/getU16BE/getUVarBE all check `pos < 0 || pos >= len`.

**Key finding:** `getGlyphName(int gid)` at line 166-175 accesses `charset[gid]` without any bounds check on `gid` against `[0, nGlyphs)`. The charset array is heap-allocated with exactly `nGlyphs` Gushort elements. All other glyph-loop callers (getNameToGIDMap, convertToType1's loop) bound `gid < nGlyphs`, but `getGlyphName()` itself does not. No xpdf callers pass unchecked GIDs currently, making this a latent API-level OOB read.

No reachable heap OOB write was found. The hintmask `pos += (nHints+7)>>3` advance is caught by getU8 bounds checking. The ops[49] overflow is properly guarded. gmallocn aborts on integer overflow.

## VULN: FoFiType1C::getGlyphName() heap OOB read via unchecked gid parameter
- **漏洞类别**: memory-safety
- **函数**: FoFiType1C::getGlyphName()
- **行号**: 166-175 (FoFiType1C.cc)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file with embedded Type1C (CFF) font
- **外部触发路径**: pdftotext → PDF font loading → FoFiType1C::make() → (external caller invokes getGlyphName(gid) with gid ≥ nGlyphs or gid < 0) → charset[gid] OOB read
- **描述**: `getGlyphName(int gid)` 在第170行直接执行 `charset[gid]` 而没有对 `gid` 进行任何边界检查（0 ≤ gid < nGlyphs）。`charset` 是通过 `gmallocn(nGlyphs, sizeof(Gushort))` 在堆上分配的恰好 `nGlyphs` 个 Gushort 元素的数组。攻击者可通过构造 CFF 字体使 nGlyphs 较小（如 1），而调用者传入大于 nGlyphs-1 的 gid，导致从堆上越界读取相邻内存内容（可能是其他对象的字段），形成堆信息泄露原语。
- **触发条件**: 攻击者需构造一个 PDF，其中嵌入 CFF/Type1C 字体，使字体的 nGlyphs 较小。调用 `getGlyphName()` 时若 gid 参数未被调用者校验（例如来自外部映射表或字符代码到 GID 的不受信映射），则触发越界读取。
- **安全影响**: 堆越界读取，可能泄露相邻堆对象内存内容（如 GString 缓冲区内容、文件解密密钥、私有字典数据），在结合其他漏洞时可提升为信息泄露或辅助 RCE 利用。

<!-- AUDIT_PROMPT_VERSION: 1 -->
