Now I have everything I need. Let me analyze the complete code carefully.

**Batch 1 analysis (lines 154–223 `parse2`):**
- `n1` comes from `PSTokenizer::getToken` into a 256-byte stack buffer; the check `n1 >= 4 && (n1 & 1) == 0` means minimum `n1 = 4`.
- `nBytes = (n1 - 2) / 2` → minimum `nBytes = 1`, maximum `nBytes = (255-2)/2 = 126`.
- `sscanf(tok+1, "%x", &start/end)` fills `Guint` (32-bit unsigned) → `end` can be `0xFFFFFFFF` with token `<FFFFFFFF>` (n1=10, passes validation).
- `addCIDs(start, end, n1, ...)` is called with attacker-controlled `start`, `end`, `nBytes`.

**Batch 2 analysis (lines 321–354 `addCIDs`):**
```cpp
Guint start1, end1, i, j, k;

start1 = start & 0xffffff00;
end1   = end   & 0xffffff00;
for (i = start1; i <= end1; i += 0x100) {   // ← CRITICAL
    ...
}
```
All of `i`, `start1`, `end1` are **`Guint` (unsigned 32-bit)**. When `end = 0xFFFFFFFF`:
- `end1 = 0xFFFFFF00`
- After the last valid iteration (`i = 0xFFFFFF00`), `i += 0x100` → `0x100000000` wraps to **`0x00000000`** in 32-bit unsigned arithmetic
- Check: `0x00000000 <= 0xFFFFFF00` → **TRUE** → **infinite loop**

In each outer iteration the inner trie-allocation loop also runs (allocating 256-entry vectors per level), so memory is continuously allocated in addition to CPU spinning.

**Trigger path (confirmed via GfxFont.cc:1801):**
```
pdftotext → PDF Type 0 font parsing → GfxFont.cc:CMap::parse() 
  → CMap::parse(cache, collection, stream, usedCMaps)    [CMap.cc:119]
  → parse2()                                             [CMap.cc:154]
  → addCIDs(0, 0xFFFFFFFF, 4, 1)                        [CMap.cc:214]
  → INFINITE LOOP in outer for-loop                      [CMap.cc:328]
```

**Attack payload (embedded CMap stream in PDF):**
```
/CMapName /Attack def
1 begincidrange
<00000000> <FFFFFFFF> 1
endcidrange
```
Token `<FFFFFFFF>` passes all validation (`n1=10, n1>=4, n1&1==0`); `sscanf("FFFFFFFF", "%x", &end)` → `end = 0xFFFFFFFF`; `nBytes = 4`. This is a fully attacker-controlled path with no mitigation.

## VULN: Infinite Loop DoS via Unsigned Integer Wrap in CMap::addCIDs (begincidrange)
- **漏洞类别**: memory-safety
- **函数**: CMap::addCIDs()
- **行号**: 321-354 (核心循环 328)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-835 (Loop with Unreachable Exit Condition)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file (embedded CMap stream in Type 0 font)
- **外部触发路径**: pdftotext(input.pdf) → PDFDoc::displayPages() → Gfx rendering → GfxFont.cc:1801 CMap::parse(NULL, collection, &obj1) → CMap::parse(cache, collection, Stream*, usedCMaps) [CMap.cc:119] → parse2() [CMap.cc:154] → begincidrange block sscanf → addCIDs(0, 0xFFFFFFFF, 4, 1) [CMap.cc:214] → outer for-loop unsigned wrap [CMap.cc:328]
- **描述**: `addCIDs()` 中外层循环变量 `i`、`end1` 均为 `Guint`（无符号 32 位整数）。当攻击者在 `begincidrange` 块中将终止码点设为 `<FFFFFFFF>`（通过 `sscanf` 解析为 `end=0xFFFFFFFF`），`end1 = end & 0xffffff00 = 0xFFFFFF00`。循环在 `i=0xFFFFFF00` 执行最后一次正常迭代后，`i += 0x100` 产生无符号溢出：`0xFFFFFF00 + 0x100 = 0x100000000`，截断为 `0x00000000`；此时循环条件 `0x00000000 <= 0xFFFFFF00` 为 TRUE，循环永不退出。每次外层迭代还可能触发内层 `gmallocn(256, sizeof(CMapVectorEntry))` 分配，导致内存持续耗尽。
- **触发条件**: 构造包含 Type 0 字体的 PDF，其 Encoding 为内嵌 CMap 流，流中包含 `1 begincidrange <00000000> <FFFFFFFF> 1 endcidrange`。token `<FFFFFFFF>` 长度 n1=10，满足 `n1>=4 && (n1&1)==0` 校验，`nBytes=(10-2)/2=4`。无需任何特权，仅需用户执行 pdftotext。
- **安全影响**: 进程永久挂起（CPU 100% + 内存持续耗尽直至 OOM kill），造成完全拒绝服务（DoS）。在服务端批处理场景下可远程触发，拒绝整个文档处理服务。

<!-- AUDIT_PROMPT_VERSION: 1 -->
