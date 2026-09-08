Now I have full context. Let me analyze each code path carefully before writing the report.

**Batch 1 Analysis — `parse()` lines 53–107:**

- `buf[256]` on stack, `tok3` points within it → `strlen(tok3)/2` max = 127
- `nBytes ≤ 4` → range path (has no eMap concern)  
- `nBytes > 4` AND `tok2 == tok1` → eMap path, **no upper bound check against `maxExtCode = 16`**
- Loop: `eMap->code[i] = (char)x` for `i = 0..nBytes-1` — writes past `code[16]` when `nBytes > 16`

**Struct layout** (UnicodeMapExt):
```
offset 0:  Unicode u      (4 bytes)
offset 4:  char code[16]  (16 bytes)
offset 20: Guint nBytes   (4 bytes)
total: 24 bytes
```

When `nBytes > 16`, the loop overwrites `nBytes` field (i=16..19) then adjacent heap metadata (i≥20). The subsequent `eMap->nBytes = nBytes` restores nBytes, so heap metadata beyond offset 24 is the real target.

**Batch 2 Analysis — `mapUnicode()` lines 179–224:**

- Range path (lines 200–209): **has** the guard `if (n > bufSize) return 0;`
- eMap path (lines 213–221): **missing** the guard — directly copies `eMaps[i].nBytes` bytes into caller's `buf` with no size check

All callers use `char buf[8]` (confirmed: TextOutputDev.cc:924, 2200, 2326, 5800). Any eMap entry with `nBytes > 8` (which is allowed up to `maxExtCode = 16`) overflows the caller's 8-byte stack buffer by up to 8 bytes.

**Attack surface:** `GlobalParams::getUnicodeMapFile()` opens the file at the path registered for the encoding name (from `unicodeMaps` hash populated by `unicodeMap` directives in xpdfrc). The encoding name comes from PDF font dictionaries. The file content must have extended codes with `nBytes > 8` (for VULN 2) or `nBytes > 16` (for VULN 1). This requires a user or system xpdfrc that maps a PDF-attacker-reachable encoding name to a unicode map file with such entries.

---

## VULN: Missing bufSize guard in mapUnicode() eMap path — caller stack buffer overflow
- **漏洞类别**: memory-safety
- **函数**: UnicodeMap::mapUnicode()
- **行号**: 213-220
- **CWE**: CWE-120 (Buffer Copy without Checking Size of Input)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted PDF file + unicode map file with nBytes 9–16
- **外部触发路径**: pdftotext main() → PDFDoc → TextOutputDev::beginString/endString → uMap->mapUnicode(ch->c, buf, sizeof(buf)) where buf is char buf[8] on stack (TextOutputDev.cc:924/2200/2326/5800) → eMap path writes eMaps[i].nBytes bytes without checking bufSize
- **描述**: `mapUnicode()` 的 range 路径在第 201 行有明确的 `if (n > bufSize) return 0;` 保护，但 eMap 路径（行 215–219）完全缺少同等检查。当 `eMaps[i].nBytes`（来自 unicode map 文件，合法范围 5–16 = maxExtCode）超过调用方 `bufSize`（所有调用方均为 8 字节栈缓冲区）时，循环 `buf[j] = eMaps[i].code[j]` 越界写入调用方的栈帧，最多溢出 8 字节（nBytes=16 时）。
- **触发条件**: PDF 字体字典中的编码名称（如 `Encoding` 条目）映射到一个 unicode map 文件，该文件包含 nBytes > 8 的扩展编码条目（nBytes 9–16 在 xpdf 设计上完全合法，maxExtCode=16）。攻击者需控制 xpdfrc 中的 unicodeMap 指令或目标系统的 unicode map 文件内容。
- **安全影响**: 调用方 8 字节栈缓冲区溢出（最多 8 字节），覆盖相邻栈变量/返回地址，在启用 ASLR+Stack Canary 的系统上仍可能通过覆盖指针实现 RCE，或作为信息泄露手段；最差情况：任意代码执行。

## VULN: Heap buffer overflow in UnicodeMap::parse() eMap code[] array — nBytes unbounded
- **漏洞类别**: memory-safety
- **函数**: UnicodeMap::parse()
- **行号**: 78-91 (核心在 86-89)
- **CWE**: CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.0 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted unicode map file referenced by crafted PDF
- **外部触发路径**: pdftotext → UnicodeMapCache::getUnicodeMap() → UnicodeMap::parse(encodingNameA) → eMap 路径：`for (i = 0; i < nBytes; ++i) eMap->code[i] = (char)x;` 当 nBytes > 16 时越界写入堆
- **描述**: `UnicodeMapExt` 结构体中 `code[maxExtCode]` 仅有 16 字节（offset 4–19），`Guint nBytes` 字段紧跟其后（offset 20–23）。`parse()` 在 eMap 路径中（`nBytes > 4 && tok2 == tok1`）未对 `nBytes` 做上界校验（没有 `if (nBytes > maxExtCode)` 检查）。`nBytes` 由 `strlen(tok3)/2` 决定，最大 127。当 `nBytes > 16` 时，循环越界写入 `nBytes` 字段（i=16–19；虽然随后被赋值覆盖恢复）；当 `nBytes > 20` 时，写入超出整个结构体，破坏相邻堆块元数据，可被利用实现堆布局操控。
- **触发条件**: 目标系统 xpdfrc 中存在 `unicodeMap <EncodingX> /path/to/file` 配置，且 PDF 字体引用 EncodingX；该 unicode map 文件包含一条两 token 行，其十六进制字符串长度 > 32（nBytes > 16）。攻击者需同时控制 PDF 和 unicode map 文件（或社会工程使受害者使用含恶意条目的 xpdfrc）。
- **安全影响**: 堆元数据破坏，可结合堆喷技术实现任意代码执行（RCE）；最低影响为程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
