I've completed a thorough analysis of `tiff2rgba.c` and its key library dependencies. Here are the confirmed findings:

**Key findings:**

In `cvt_by_tile()` line 157: `raster_size = multiply(multiply(tile_width, tile_height), sizeof(uint32))` — On 64-bit Linux (`tsize_t = int32`, `sizeof(uint32) = size_t = uint64_t`), the outer `TIFFSafeMultiply(tsize_t, inner, sizeof(uint32))` check is broken. When `inner * 4 > INT32_MAX`, the product is computed in 64-bit, the check compares `(int32_t)(product/4) == (int32_t)(inner)` which trivially passes since `inner ≤ INT32_MAX`, then the returned `(tsize_t)(product)` silently truncates to low 32 bits, producing a drastically undersized allocation. For tile_width = tile_height = 32769: expected ~4.3 GB, allocated 786 KB. Same bug exists in `cvt_by_strip()` line 265.

## VULN: cvt_by_tile TIFFSafeMultiply int32 Truncation → Heap Overflow
- **漏洞类别**: memory-safety
- **函数**: cvt_by_tile()
- **行号**: 157-164
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2rgba main() -b flag → tiffcvt() → cvt_by_tile() → TIFFSafeMultiply(tsize_t, inner_result, sizeof(uint32)) → _TIFFmalloc(truncated_size) → TIFFReadRGBATile() → TIFFRGBAImageGet() → gtTileContig() → (*put)() writes tile_width*tile_height*4 bytes into undersized buffer
- **描述**: 在64位系统上 `tsize_t = int32`（有符号32位）而 `sizeof(uint32) = size_t = uint64_t`（无符号64位）。`TIFFSafeMultiply(tsize_t, inner, sizeof(uint32))` 宏将 `inner * sizeof(uint32)` 在64位算术中计算（因 size_t 类型提升），则溢出检查 `(tsize_t)((v*m)/m) == (tsize_t)(v)` 两侧均等于 `inner`（因为 `inner ≤ INT32_MAX` 可准确截断回 int32），检查错误通过。最终 `(tsize_t)(inner * 4)` 将64位乘积截断为32位低位，返回远小于实际所需大小的值（如对 tile_width=tile_height=32769，应分配 4295753732 字节，实际分配 786436 字节）。后续 `TIFFReadRGBATile` 向该严重不足的堆缓冲区写入 `tile_width * tile_height * 4 ≈ 4.3GB` 字节，造成大规模堆越界写。
- **触发条件**: 使用 `-b` 参数运行 `tiff2rgba`（process_by_block=1），输入为瓦片化 TIFF 文件，且 `TILEWIDTH * TILELENGTH` 处于区间 `(536870911, 2147483647]`（即内层乘积为正 int32 但乘以4后超过 INT32_MAX）。例如：TILEWIDTH=TILELENGTH=32769（0x8001）。
- **安全影响**: 大规模堆缓冲区溢出，覆盖堆元数据及相邻对象，可通过精心控制溢出数据实现任意代码执行（RCE）；在 ASLR+PIE 下至少造成稳定 DoS（进程崩溃）。

## VULN: cvt_by_strip TIFFSafeMultiply int32 Truncation → Heap Overflow
- **漏洞类别**: memory-safety
- **函数**: cvt_by_strip()
- **行号**: 265-272
- **CWE**: CWE-190 (Integer Overflow or Wraparound)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2rgba main() -b flag → tiffcvt() → cvt_by_strip() → TIFFGetField(ROWSPERSTRIP) → multiply(multiply(width, rowsperstrip), sizeof(uint32)) → TIFFSafeMultiply truncation → _TIFFmalloc(undersized) → TIFFReadRGBAStrip() → TIFFRGBAImageGet() → gtStripContig() → (*put)() writes width*rowsperstrip*4 bytes into undersized buffer
- **描述**: 与 cvt_by_tile 同根因：`multiply(multiply(width, rowsperstrip), sizeof(uint32))` 中外层 `TIFFSafeMultiply(tsize_t, inner, sizeof(uint32))` 在64位系统上因类型提升导致溢出检查失效，返回截断后的极小值。`rowsperstrip` 直接来自攻击者控制的 TIFF 文件 tag（TIFFTAG_ROWSPERSTRIP），`width` 来自 TIFFTAG_IMAGEWIDTH。当 `width * rowsperstrip` 处于漏洞区间时，分配的 raster 缓冲区严重不足，后续 `TIFFReadRGBAStrip` 对整个条带的解码写入造成堆越界。
- **触发条件**: 使用 `-b` 参数运行 `tiff2rgba`，输入为条带（strip-based）TIFF 文件，且 TIFF 中设置 `IMAGEWIDTH * ROWSPERSTRIP` 处于区间 `(536870911, 2147483647]`（如 IMAGEWIDTH=ROWSPERSTRIP=32769）。
- **安全影响**: 堆缓冲区大规模溢出（写入量远超分配量），可实现任意代码执行（RCE）或稳定崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
