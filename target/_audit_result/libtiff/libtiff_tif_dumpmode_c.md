Now I have enough context to complete the analysis. Let me verify the exact type of `nrows * tif_scanlinesize` and the overflow behavior.

**Group analysis — tif_dumpmode.c (127 lines total, all read):**

Key findings per function:

**DumpModeEncode (lines 37–65):** Standard bounded copy loop. Checks `tif_rawcc + n > tif_rawdatasize` before each copy; flushes when full. No overflow visible — `n` is safely clamped. No bug here.

**DumpModeDecode (lines 70–91):** Checks `tif_rawcc < cc` before memcpy. Safe when state is consistent. Vulnerable ONLY if rawcc/rawcp are corrupted upstream.

**DumpModeSeek (lines 96–102) — VULNERABLE:**
```c
tif->tif_rawcp += nrows * tif->tif_scanlinesize;  // line 99
tif->tif_rawcc -= nrows * tif->tif_scanlinesize;  // line 100
```
- `nrows` is `uint32`; `tif->tif_scanlinesize` is `tsize_t = int32` (signed).
- Per C arithmetic conversion rules (unsigned wins same rank): both become `uint32`; the multiplication is done mod 2³².
- **No overflow check is performed on this multiplication.**
- When the uint32 product ≥ 0x80000000 (either naturally or via wrap), converting it to int32 for the `-=` on `tif_rawcc` (int32) yields a negative number, so `tif_rawcc` is **increased** rather than decreased.
- Simultaneously `tif_rawcp` is advanced by the raw uint32 offset — potentially 2 GB – 4 GB past the heap allocation.
- On the next call to `DumpModeDecode`, the check `tif_rawcc < cc` sees an inflated rawcc and **passes**, then executes `_TIFFmemcpy(buf, tif_rawcp, cc)` from the out-of-bounds address → **OOB read**.

**Concrete trigger (nrows=0x55555553, scanlinesize=3):**
- Product = 0xFFFFFFFF → int32 = −1 → rawcc += 1 (bypasses check); rawcp += 4 GB − 1 (far past 9-byte strip buffer).
- `tif_rawcc` (e.g., 7) ≥ `cc` (3) → DumpModeDecode proceeds → crash (SIGSEGV) or info-leak.

**Call chain:** `tiffsplit main()` → `TIFFOpen()` → `TIFFReadScanline()` → `TIFFSeek()` (tif_read.c:88) → `(*tif->tif_seek)(tif, row−tif_row)` = `DumpModeSeek()`.

`nrows = row − tif_row` where RowsPerStrip is attacker-controlled from the TIFF file. StripByteCount can be set to a small value (e.g., 9 bytes), while RowsPerStrip is set to ~0x55555556, so `nrows` can reach 0x55555553.

## VULN: DumpModeSeek Integer Overflow → Out-of-Bounds Read
- **漏洞类别**: memory-safety
- **函数**: DumpModeSeek()
- **行号**: 97-101
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() -> TIFFOpen() -> TIFFReadScanline() -> TIFFSeek() [tif_read.c:88] -> (*tif->tif_seek)(tif, row - tif->tif_row) -> DumpModeSeek() [tif_dumpmode.c:99-100] -> DumpModeDecode() [tif_dumpmode.c:87]
- **描述**: `DumpModeSeek` 在 `tif_rawcp` 和 `tif_rawcc` 上执行的算术运算 `nrows * tif->tif_scanlinesize` 缺乏溢出保护。`nrows` 类型为 `uint32`，`tif_scanlinesize` 类型为 `tsize_t`（即 `int32`，有符号）。按 C 语言 usual arithmetic conversion 规则，`int32` 被转换为 `uint32`，乘积以 32 位无符号截断（mod 2³²）。当截断后的 uint32 乘积落入 [0x80000000, 0xFFFFFFFF] 范围时，将其作为 `int32` 赋给 `tif_rawcc -= (int32)product` 会得到负数，相减变为相加，导致 `tif_rawcc` 不降反升；同时 `tif_rawcp` 以该 uint32 值（最大 4 GB − 1）前进，大幅越过堆上 raw data 缓冲区的末尾。随后 `DumpModeDecode` 检查 `tif_rawcc < cc` 因 rawcc 被错误抬高而不触发，继而调用 `_TIFFmemcpy(buf, tif_rawcp, cc)`，从越界地址读取数据，造成堆外越界读。
- **触发条件**: 攻击者构造 TIFF 文件，令 Compression=NONE（DumpMode），将 RowsPerStrip 设置为极大值（如 0x55555556），StripByteCount 设置为极小值（如 9 字节，对应 3 行），ImageLength 足够大；然后请求读取编号为 `tif_row + 0x55555553` 的扫描行。此时 `nrows = 0x55555553`，`tif_scanlinesize = 3`，乘积 = 0xFFFFFFFF（uint32），触发上述 rawcc/rawcp 不一致，导致越界读。
- **安全影响**: 进程崩溃（SIGSEGV，DoS）；在特定堆布局下可能读取相邻堆内存，造成信息泄露；若被集成于网络服务（如图像处理后端），可被远程触发。

<!-- AUDIT_PROMPT_VERSION: 1 -->
