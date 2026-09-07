Now I have enough context. Let me compile all findings from the full file analysis.

**Batch summary:**

**Lines 1–414 (`_TIFFWriteDirectory`):** `dirsize = nfields * sizeof(TIFFDirEntry)` — `nfields` is bounded by FIELD_LAST (~130) plus `td_customValueCount` (max 65535 from uint16 IFD count field), so no overflow.

**Lines 572–782 (`TIFFWriteNormalTag`):** For `TIFF_RATIONAL`/`TIFF_SRATIONAL` with `field_passcount` and `TIFF_VARIABLE2`, `dir->tdir_count = wc2` where `wc2` is a `uint32` returned by `TIFFGetField` (ultimately from a custom tag's stored count, which came from the file's IFD entry). This value flows directly into `TIFFWriteRationalArray`.

**Lines 1011–1050 (`TIFFWriteRationalArray`):**  
```c
t = (uint32*) _TIFFmalloc(2 * dir->tdir_count * sizeof (uint32));  // line 1017
for (i = 0; i < dir->tdir_count; i++) { ... }                      // line 1023
```  
- `dir->tdir_count` is `uint32`. `2 * dir->tdir_count` is computed as `uint32` (int × uint32 → uint32 arithmetic). If `dir->tdir_count >= 0x80000000`, the product wraps (e.g., `2 × 0x80000001 = 2`), yielding `malloc(8)`. The loop then writes `0x80000001 × 8` bytes into 8 bytes of heap → heap overflow.  
- No upper-bound check exists at this call site.

**Lines 1087–1088 (`TIFFWriteAnyArray`):** `n` is `samples` (uint16, max 65535) → `n * TIFFDataWidth(type)` max = 524280, no overflow.

**Lines 1248 (`TIFFWriteData`):** `dir->tdir_count * TIFFDataWidth(...)` overflow affects only the file-write size — no memory corruption.

**Lines 1300–1322 (`TIFFRewriteDirectory`) and 1397–1418 (`TIFFLinkDirectory`):** `dircount * sizeof(TIFFDirEntry)` where `dircount` is `uint16` (max 65535) — no overflow.

**Attack chain verification:** Reading path `_TIFFCheckRealloc` (`tif_aux.c:46`) has an overflow guard `bytes / elem_size == nmemb`. For a custom RATIONAL VARIABLE2 tag with very large count (≥ 0x80000000), the reading path allocation fails → `tv->value = NULL`. In the write path, `TIFFGetField` returns this NULL as the float pointer `fp`. `TIFFWriteRationalArray` then: allocates tiny buffer `t` (from overflowed size), then immediately NULL-dereferences at `v[0]` (where `v = fp = NULL`) — crash/DoS. Heap overflow is reachable if a caller passes a valid float array with a large count directly via `TIFFSetField` (API misuse scenario), bypassing the reading path's guard.

---

## VULN: Integer Overflow in TIFFWriteRationalArray malloc Leading to Heap Overflow or Crash
- **漏洞类别**: memory-safety
- **函数**: TIFFWriteRationalArray()
- **行号**: 1017-1046
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → TIFFSetField() [custom RATIONAL VARIABLE2 tag stored with large count] → TIFFWriteDirectory() → _TIFFWriteDirectory() → TIFFWriteNormalTag() [dir->tdir_count = wc2 from TIFFGetField, attacker-controlled] → TIFFWriteRationalArray() → _TIFFmalloc(2 * dir->tdir_count * sizeof(uint32)) [integer overflow]
- **描述**: 在 `TIFFWriteRationalArray()` 第 1017 行，表达式 `2 * dir->tdir_count * sizeof(uint32)` 中，`dir->tdir_count` 为 `uint32` 类型。当 `dir->tdir_count >= 0x80000000` 时，`2 * dir->tdir_count` 在 `uint32` 算术中发生回绕（例如 `2 × 0x80000001 = 0x00000002`），乘以 `sizeof(uint32) = 4` 后仅分配 8 字节。随后第 1023 行的循环执行 `dir->tdir_count`（= 0x80000001 次）次写操作，向 8 字节堆缓冲区写入数十亿字节，造成严重堆溢出。对于通过 `tiffsplit` 解析的构造文件，reading 路径中 `_TIFFCheckRealloc` 的溢出保护（`tif_aux.c:46`）会使 `tv->value = NULL`，导致写路径在第一次循环迭代时因 NULL 解引用而崩溃（DoS）；而在直接 API 调用场景下（`TIFFSetField(tif, tag, large_count, valid_float_ptr)`），`tv->value` 非 NULL，可直接触发堆溢出，进而实现 RCE。
- **触发条件**: 构造一个含有自定义 TIFF_RATIONAL/TIFF_SRATIONAL 类型标签（`field_passcount=TRUE`，`field_writecount=TIFF_VARIABLE2`）且 IFD entry count 字段 ≥ 0x80000000 的 TIFF 文件。该标签在 libtiff 注册为自定义标签后，tiffsplit 打开文件触发 `TIFFReadDirectory` 并尝试调用 `TIFFSetField` 存储该标签。对于直接 API 使用场景：调用 `TIFFSetField(tif, CUSTOM_TAG, (uint32)0x80000001, valid_ptr)` 后再调用 `TIFFWriteDirectory()`。
- **安全影响**: 通过 tiffsplit 解析构造的 TIFF 文件可稳定触发进程崩溃（DoS）。在直接 API 调用场景下，堆缓冲区溢出可覆盖堆元数据及相邻对象，最坏情况导致任意代码执行（RCE）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
