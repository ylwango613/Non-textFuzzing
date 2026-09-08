I have gathered sufficient context. Let me now synthesize the findings.

**Analysis Summary:**

**File analysis - UnicodeMap.cc:**

**Group 1 (lines 34-108, `parse()`):**
- Line 65: `nBytes = (int)strlen(tok3) / 2` — derived from file input, max 127 (buf is 256 chars)
- Line 66: `if (nBytes <= 4)` → ranges path
- Lines 78-91: eMap path for single-char mappings — `eMap->nBytes = nBytes` with NO upper-bound check against `maxExtCode = 16`
- Lines 86-89: `for (i = 0; i < nBytes; ++i) { eMap->code[i] = (char)x; }` — writes into `char code[16]`; if nBytes > 16, **heap buffer overflow** past end of struct

**Group 2 (lines 179-224, `mapUnicode()`):**
- Lines 201-203: ranges path has a guard `if (n > bufSize) { return 0; }`
- Lines 213-220: eMap path **omits the bufSize guard entirely**
- Loop `buf[j] = eMaps[i].code[j]` writes up to `n = eMaps[i].nBytes` bytes to caller's `buf`
- All callers (TextOutputDev.cc:924, pdfinfo.cc:371,471, PSOutputDev.cc:5976) declare `char buf[8]`
- If any eMap entry has nBytes ≥ 9 (valid per maxExtCode=16), a **stack buffer overflow** occurs in the caller

**Attack surface:** UnicodeMap files are loaded from `xpdfrc` configuration, not directly from PDF content. However, the encoding name can be specified in PDF font dictionaries and then resolved via `getUnicodeMap()`, which loads the file configured in xpdfrc. If a user-configured UnicodeMap file has long output sequences, both vulnerabilities are reachable.

## VULN: Heap Buffer Overflow in UnicodeMap::parse() via Oversized eMap Code Entry
- **漏洞类别**: memory-safety
- **函数**: UnicodeMap::parse()
- **行号**: 78-91 (UnicodeMap.cc)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 6.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted UnicodeMap configuration file loaded during PDF processing
- **外部触发路径**: pdftotext → TextOutputDev → GlobalParams::getUnicodeMap() → UnicodeMapCache::getUnicodeMap() → UnicodeMap::parse() → heap overflow at eMap->code[i]
- **描述**: 在 `UnicodeMap::parse()` 的 eMap 分支（行 78-91），变量 `nBytes` 由 `strlen(tok3)/2` 计算（最大127），仅通过 `nBytes <= 4` 区分 range/eMap 路径，但写入 `UnicodeMapExt::code[maxExtCode]`（即 `char code[16]`）时没有对 `nBytes > maxExtCode (16)` 的上界检查。当输入文件行中单字符映射的十六进制串超过 32 个十六进制字符（即 nBytes > 16）时，`for (i = 0; i < nBytes; ++i) { eMap->code[i] = ... }` 向堆上分配的 `UnicodeMapExt` 结构体尾部之后写入，造成堆溢出。
- **触发条件**: 在 xpdfrc 配置的 unicodeMap 文件中，放置一行形如 `0x1234 AABBCCDDEEFF00112233445566778899AABB`（hex 串超过 32 字符 = nBytes 17+），且该 encoding 被处理的 PDF 字体引用，触发 xpdf 加载并解析该 unicodeMap 文件。
- **安全影响**: 攻击者可在 heap 上任意写超出 UnicodeMapExt 结构体边界的字节，在特定 heap 布局下可覆盖相邻堆元数据或对象指针，最终可能导致任意代码执行（RCE）或进程崩溃（DoS）。

## VULN: Stack Buffer Overflow in UnicodeMap::mapUnicode() via Missing bufSize Check in eMap Path
- **漏洞类别**: memory-safety
- **函数**: UnicodeMap::mapUnicode()
- **行号**: 213-220 (UnicodeMap.cc)
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 6.7 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted UnicodeMap configuration file loaded during PDF processing
- **外部触发路径**: pdftotext → TextOutputDev::encodeFragment() / computeLinePhysWidth() (char buf[8]) → UnicodeMap::mapUnicode(u, buf, 8) → eMap path (lines 213-220) → stack overflow
- **描述**: `mapUnicode()` 中 ranges 路径（行 201-203）有 `if (n > bufSize) { return 0; }` 保护，但 eMap 路径（行 213-220）**完全缺少**该检查。当 `eMaps[i].nBytes > bufSize` 时，循环 `for (j = 0; j < n; ++j) { buf[j] = eMaps[i].code[j]; }` 向调用者提供的 `buf` 末端之后写入。所有调用者（TextOutputDev.cc、pdfinfo.cc、PSOutputDev.cc）均声明 `char buf[8]` 并传入 `sizeof(buf) = 8`。任何 eMap 条目的 nBytes 落在 [9, 16] 区间（合法的结构体存储范围）即可触发此栈溢出，无需先触发堆溢出。
- **触发条件**: 在 xpdfrc 配置的 unicodeMap 文件中，放置一行形如 `0x1234 AABBCCDD0011223344`（hex 串恰好产生 nBytes = 9-16 的单字符 eMap 条目），且该 encoding 被 PDF 字体引用，让 xpdf 对该 Unicode 码点调用 mapUnicode()。
- **安全影响**: 覆盖调用栈上 `buf[8]` 之后的数据（返回地址、帧指针、局部变量），在 no-ASLR 或 ASLR 可暴力破解的环境下可导致任意代码执行（RCE）；在有保护的现代系统上至少导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
