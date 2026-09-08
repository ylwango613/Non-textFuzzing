Now I have all the context needed. Let me analyze the CCITTFaxStream decode logic carefully, with focus on the table lookup bounds in both `endOfBlock=true` and `endOfBlock=false` paths.

**Group 1 — Stream-CCITT.h tables (lines 1–464):**
Pure static lookup tables. Sizes:
- `twoDimTab1[128]`
- `whiteTab1[32]`, `whiteTab2[512]`
- `blackTab1[128]`, `blackTab2[192]`, `blackTab3[64]`

No direct vulnerability in the .h file itself.

**Group 2 — Constructor/allocations (Stream.cc lines 1563–1596):**
`codingLine = gmallocn(columns + 1, sizeof(int))`, `refLine = gmallocn(columns + 3, sizeof(int))`. Columns is clamped: `if (columns > INT_MAX - 3) columns = INT_MAX - 3`. Looks correct.

**Group 3 — `getTwoDimCode` (lines 2111–2143):**
`endOfBlock=true`: `lookBits(7)` → 7-bit code → `twoDimTab1[code]` with `twoDimTab1[128]`. Index 0–127. Safe.
`endOfBlock=false`: shifts to 7 bits then same lookup. Safe.

**Group 4 — `getWhiteCode` endOfBlock=true (lines 2152–2165):**
`lookBits(12)` → 12-bit code. Guards: `(code >> 5) == 0` → code < 32 → `whiteTab1[code]` (0–31), else `whiteTab2[code >> 3]` (0–511 for whiteTab2[512]). Safe.

**Group 4b — `getWhiteCode` endOfBlock=false (lines 2167–2194):** ← **CRITICAL FINDING**
```c
for (n = 1; n <= 9; ++n) {
    code = (short)(code << (9 - n));   // shifts to 9 bits → index 0–511 → whiteTab2[512] ✓
    p = &whiteTab2[code];
}
for (n = 11; n <= 12; ++n) {
    if (n < 12)
        code = (short)(code << (12 - n));  // shifts to 12 bits → index 0–4095
    p = &whiteTab1[code];   // ← whiteTab1 has ONLY 32 entries! OOB up to index 4095
```
**`whiteTab1[code]` with 12-bit index (0–4095) but `whiteTab1` has 32 entries.**

**Group 5 — `getBlackCode` endOfBlock=true (lines 2211–2226):** 
All guarded: code>>7==0→`blackTab1[0..127]`, code>>9==0→`blackTab2[(code>>1)-64]` (0–191), else `blackTab3[code>>7]` (4–63). Safe.

**Group 5b — `getBlackCode` endOfBlock=false (lines 2227–2280):** ← **CRITICAL FINDING**
```c
for (n = 7; n <= 12; ++n) {          // shifts to 12 bits: index 0–4095
    code = (short)(code << (12 - n));
    if (code >= 64)
        p = &blackTab2[code - 64];   // blackTab2 has 192 entries; code-64 up to 4031 → OOB
```
```c
for (n = 10; n <= 13; ++n) {         // shifts to 13 bits: index 0–8191
    code = (short)(code << (13 - n));
    p = &blackTab1[code];            // blackTab1 has 128 entries; code up to 8191 → OOB
```

**Trigger path:** PDF sets `/CCITTFaxDecode` with `/EndOfBlock false` → `endOfBlock = gFalse` → non-default branch taken in `getWhiteCode()`/`getBlackCode()`.

**Impact:**
- `whiteTab1` OOB: max byte offset = 4095 × 4 = 16380 bytes past array start; `whiteTab1` is 128 bytes; remaining static arrays account for ~4096 bytes — reads 12284 bytes into unknown program memory (potentially unmapped page → SIGSEGV DoS).
- `blackTab2`/`blackTab1` OOB similar.
- Garbage `p->n` (short) returned as run-length: accumulated in `code1 += code3 = getWhiteCode()` with `while (code3 >= 64)`; if OOB returns make-up code ≥ 64 repeatedly until stream EOF, causes tight loop DoS.
- Not RCE (read not write), but DoS/crash + potential adjacent-memory info leak.

## VULN: OOB Read in getWhiteCode() via CCITTFax EndOfBlock=false
- **漏洞类别**: memory-safety
- **函数**: CCITTFaxStream::getWhiteCode()
- **行号**: 2181-2194
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: pdftotext → PDFDoc::displayPages() → Gfx::display() → Stream::makeFilter() → CCITTFaxStream::getChar()/readRow() → CCITTFaxStream::getWhiteCode() → OOB read of whiteTab1[]
- **描述**: 在 `getWhiteCode()` 的 `endOfBlock = false` 分支中（Stream.cc:2181–2194），代码对 n=11、12 比特的白码进行查表时，将 n 位码值左移至 12 位，得到最大 4095 的索引，然后直接用 `p = &whiteTab1[code]` 访问 `whiteTab1`。但 `whiteTab1` 只有 32 个元素（`CCITTCode whiteTab1[32]`，Stream-CCITT.h:109）。合法路径（`endOfBlock = true`）通过 `(code >> 5) == 0` 守卫确保索引 ≤ 31，而 `endOfBlock = false` 路径没有此守卫，导致越界读，最大偏移 4095 × 4 = 16380 字节，大幅超出相邻静态数组范围（`whiteTab2` 等共 ~4096 字节），可能读入未映射内存页触发 SIGSEGV。
- **触发条件**: 攻击者构造 PDF，使用 CCITTFaxDecode（或 CCF）流过滤器并在参数字典中设置 `/EndOfBlock false`；同时在流数据中构造不匹配任何合法白码的比特模式，使解码器进入 n=11/12 的循环分支并执行 `whiteTab1[code]` 越界读。
- **安全影响**: 越界读取静态数据段以外的内存：轻则读取相邻内存泄露少量程序数据（信息泄露）；重则访问未映射页导致 SIGSEGV，xpdf/pdftotext 进程崩溃（DoS）。此外，OOB 返回的 garbage run-length 值若 ≥ 64 则导致 do-while 解码循环持续旋转直到流耗尽，形成 CPU 消耗型 DoS。

## VULN: OOB Read in getBlackCode() via CCITTFax EndOfBlock=false
- **漏洞类别**: memory-safety
- **函数**: CCITTFaxStream::getBlackCode()
- **行号**: 2242-2270
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PDF file
- **外部触发路径**: pdftotext → PDFDoc::displayPages() → Gfx::display() → Stream::makeFilter() → CCITTFaxStream::readRow() → CCITTFaxStream::getBlackCode() → OOB read of blackTab2[]/blackTab1[]
- **描述**: 在 `getBlackCode()` 的 `endOfBlock = false` 分支中存在两处越界读：(1) n=7–12 的循环（Stream.cc:2242–2256）将码值左移至 12 位后，以 `blackTab2[code - 64]` 访问，code-64 最大可达 4031，而 `blackTab2` 只有 192 个元素（Stream-CCITT.h:363）；(2) n=10–13 的循环（Stream.cc:2258–2270）将码值左移至 13 位后，以 `blackTab1[code]` 访问，code 最大可达 8191，而 `blackTab1` 只有 128 个元素（Stream-CCITT.h:301）。合法的 `endOfBlock = true` 路径使用位掩码守卫（`code >> 7 == 0`，`code >> 9 == 0`）将索引限制在合法范围内，而 `endOfBlock = false` 路径没有这些守卫。
- **触发条件**: 攻击者构造 PDF，包含 `/EndOfBlock false` 的 CCITTFaxDecode 流，并在流比特数据中嵌入与已知黑码均不匹配的比特模式，迫使解码器进入 n=7–12 或 n=10–13 循环并执行越界 `blackTab2`/`blackTab1` 访问。
- **安全影响**: 越界读取进程内存：可能导致 SIGSEGV 崩溃（DoS），或读取静态数据段以外的相邻内存（轻微信息泄露）。garbage 返回值亦可能导致解码循环 DoS（CPU 旋转至流耗尽）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
