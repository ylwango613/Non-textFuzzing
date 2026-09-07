I now have a complete picture. Let me write the final audit report.

**Analysis summary across all batches:**

- **Lines 34–61 (`summarize()`, `multiply()`)**: Both helpers correctly detect overflow via the division-check technique. Even on 64-bit (where the product is 64-bit before truncation to uint32), the check is mathematically sound and cannot be fooled for any practical TIFF image dimension. These helpers are safe.

- **Lines 88–101 (`TIFFNumberOfStrips()`)**: Uses `TIFFhowmany()` (overflow-safe macro) + `multiply()`. Safe.

- **Lines 107–166 (`TIFFVStripSize()`)**: Uses `multiply()` + `summarize()` + explicit signed-overflow guard (`if ((tsize_t)stripsize < 0) ... = 0`). Safe.

- **Lines 172–186 (`TIFFRawStripSize()`)**: Assigns `toff_t` (uint32) to `tsize_t` (int32); values > INT32_MAX become negative and are caught by `bytecount <= 0`. No bounds check on `strip` index, but callers are expected to validate it.

- **Lines 197–216 (`TIFFStripSize()`, `_TIFFDefaultStripSize()`)**: Delegated to `TIFFVStripSize()`. Safe.

- **Lines 242–279 (`TIFFScanlineSize()`)**: YCbCr path uses `TIFFhowmany()` + `multiply()` + `multiply()` + `TIFFhowmany8()`. Maximum output of `TIFFhowmany8(uint32)` is 536870912 < INT32_MAX, so tsize_t cast is always non-negative. Safe.

- **Lines 285–297 (`TIFFOldScanlineSize()`)**: Same analysis. Safe.

- **Lines 312–348 (`TIFFNewScanlineSize()`)**: **VULNERABLE.** The YCbCr branch (lines 332–336) uses raw C arithmetic—no safe `multiply()`/`summarize()` helpers. The expression `((W+H-1)/H) * (H*V+2) * B + 7) / 8 / V` performs uint32 multiplications that can overflow silently and produce an incorrect (too-small) scanline size, inconsistent with `TIFFVStripSize()` (which returns 0 on overflow). This inconsistency causes a heap OOB read in `gtStripContig()`.

- **Lines 357–372 (`TIFFRasterScanlineSize()`)**: PLANARCONFIG_SEPARATE path: `multiply(tif, TIFFhowmany8(scanline), samplesperpixel, ...)` can return a uint32 value that correctly passes the overflow check but exceeds INT32_MAX, becoming a negative `tsize_t` on the cast. No validity guard before returning.

---

## VULN: TIFFNewScanlineSize YCbCr raw-arithmetic overflow → heap OOB read in gtStripContig
- **漏洞类别**: memory-safety
- **函数**: TIFFNewScanlineSize()
- **行号**: 332-336
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: any TIFF consumer using the RGBA API (e.g. tiff2rgba, thumbnail) → TIFFRGBAImageGet() → TIFFRGBAImageGet_() → gtStripContig() [tif_getimage.c:808] → _TIFFmalloc(TIFFStripSize() = 0) → [malloc(0) returns non-NULL on Linux glibc] → TIFFNewScanlineSize() [tif_strip.c:332-336, returns large non-zero value] → put-callback reads nrow×scanline bytes from the 0-byte effective heap allocation (heap OOB read)
- **描述**: `TIFFNewScanlineSize()` computes the per-scanline byte size for contiguous YCbCr data using a single raw C arithmetic expression (lines 332–336) without the `multiply()`/`summarize()` safe helpers used everywhere else in `tif_strip.c`. For images with `imagewidth` large enough that `(imagewidth × (H×V+2) × bitspersample)` overflows `uint32`, the expression silently wraps and returns a non-zero but incorrect value (e.g. 268 435 456 bytes for imagewidth=0x20000000, BPS=12, subsampling=[1,1]). `TIFFVStripSize()` and `TIFFStripSize()`, by contrast, call `multiply()` which detects the same overflow and returns 0. In `gtStripContig()` (tif_getimage.c:808–846), the buffer is allocated with `_TIFFmalloc(TIFFStripSize() = 0)`, which on Linux glibc returns a valid but effectively 0-byte pointer; the null check on line 809 passes. `TIFFReadEncodedStrip` is capped by `TIFFVStripSize()=0` and writes no decoded bytes, yet the `put` callback (line 846) immediately reads `nrow × scanline` bytes from `buf + pos` using the inflated `TIFFNewScanlineSize()` value as `scanline`, walking far past the zero-byte allocation into adjacent heap metadata and object memory.
- **触发条件**: 攻击者构造 TIFF 文件：Photometric=YCBCR, PlanarConfig=CONTIG, not upsampled (no TIFF_UPSAMPLED flag), ImageWidth 在 0x10000000–0xFFFFFFFF 范围内，BitsPerSample 取非 2 的幂次方值（如 12），YCbCrSubSampling=[1,1]，使得 `(width × 3 × bps) mod 2^32` 产生一个非零但错误的小值（远小于真实结果），而同样参数下 `multiply()` 检测到溢出并返回 0。目标程序须通过 `TIFFRGBAImageGet()` 系列接口读取此 TIFF（tiff2rgba、thumbnail 等工具均满足）。
- **安全影响**: 堆越界读（heap OOB read）：从紧邻 `malloc(0)` 分配块的堆元数据或其他堆对象中读取最多数百 MB 的数据，并将其以 RGBA 像素形式写入调用方提供的 raster 缓冲区，造成堆布局信息泄露（可用于绕过 ASLR）。在某些进程/堆布局下亦可能引发段错误（拒绝服务）。

## VULN: TIFFRasterScanlineSize PLANARCONFIG_SEPARATE returns negative tsize_t without guard
- **漏洞类别**: memory-safety
- **函数**: TIFFRasterScanlineSize()
- **行号**: 369-371
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit/tiffcp main() → TIFFOpen() → TIFFReadDirectory() → cpImage() [tiffcp.c:1169] → TIFFRasterScanlineSize() [tif_strip.c:369-371] returns negative tsize_t → tsize_t bytes = negative_scanline × (tsize_t)UINT32_MAX_imagelength wraps to small positive → _TIFFmalloc(small) succeeds → readContigStripsIntoBuffer / readSeparateStripsIntoBuffer copies imagelength × scanlinesize bytes into under-allocated buf
- **描述**: `TIFFRasterScanlineSize()` 的 `PLANARCONFIG_SEPARATE` 分支（行 369–371）将 `multiply()` 的 `uint32` 返回值直接强制转换为 `tsize_t`（即 `int32`），且没有任何负值保护检查。当 `TIFFhowmany8(scanline) × samplesperpixel` 的乘积（虽然在 uint32 范围内未溢出，但超过 INT32_MAX）时，`multiply()` 不报告溢出（因为 `bytes/elem_size == nmemb` 成立），但 `(tsize_t)` 强转使结果变为负数（如 `samplesperpixel=5, imagewidth=UINT32_MAX, bps=1` → 返回 −1610612736）。在 `tiffcp.c` 的 `cpImage()` 中，`bytes = scanlinesize × (tsize_t)imagelength`：若攻击者将 `imagelength` 设为 `UINT32_MAX`，则 `(tsize_t)UINT32_MAX = −1`，`bytes = (−N) × (−1) = N`（一个小正数）；溢出检测条件 `bytes / (tsize_t)imagelength == scanlinesize` 在 `(N / −1 == −N)` 时满足，`_TIFFmalloc(N)` 分配极小缓冲区，随后 `fin` 回调按照真实 `imagelength × |scanlinesize|` 字节向该缓冲区写入，造成巨型堆缓冲区溢出。
- **触发条件**: 攻击者构造 TIFF 文件：PlanarConfig=SEPARATE，BitsPerSample=1，ImageWidth=UINT32_MAX（4294967295），SamplesPerPixel=5（或任意使乘积 > INT32_MAX 但 < UINT32_MAX），ImageLength=UINT32_MAX；目标程序须通过 `tiffcp`（使用 `cpImage()` 路径）处理该文件。
- **安全影响**: 堆缓冲区溢出（heap buffer overflow）：大量攻击者控制的 TIFF 条带数据被写入极小的堆分配区，可导致任意代码执行（RCE）或进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
