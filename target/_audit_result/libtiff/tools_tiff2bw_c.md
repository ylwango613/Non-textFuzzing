Now I have a complete picture. Let me analyze all vulnerabilities systematically.

**Batch 1 (lines 1–267) analysis:**

- **Line 207**: `outbuf = (unsigned char *)_TIFFmalloc(TIFFScanlineSize(out));` — no NULL check, no overflow guard.
- **Lines 230, 240**: `inbuf = (unsigned char *)_TIFFmalloc(TIFFScanlineSize(in));` — same.
- **Line 251**: `inbuf = (unsigned char *)_TIFFmalloc(3*rowsize);` where `rowsize` is `tsize_t` (int32).

**Key fact confirmed from `tiffio.h:67`**: `typedef int32 tsize_t;` — 32-bit signed integer.

**Key fact from `tif_strip.c:52-59`**: `multiply()` returns 0 on overflow, then `TIFFScanlineSize` also returns 0.

**Key fact from `tif_read.c:106-107`**: `TIFFReadScanline` decodes exactly `tif->tif_scanlinesize` bytes (which is 0 when overflow was detected).

**Key fact from `tif_unix.c:241`**: `_TIFFmalloc(0)` → `malloc(0)` → on Linux returns non-NULL valid pointer to a 0-byte allocation.

**Root Cause**: When `TIFFScanlineSize(in)` returns 0 (due to integer overflow detection in `multiply()`), `_TIFFmalloc(0)` returns a tiny heap pointer. `TIFFReadScanline` then writes 0 bytes (harmless). But then `compresspalette/compresscontig/compresssep` loops over the original raw `w` value — performing `w` iterations of reads/writes on a 0-byte allocated buffer → heap OOB.

**Thresholds**:
- PALETTE/SEPARATE: `w*8` overflows uint32 at `w >= 536870912` (2^29)
- RGB CONTIG: `w*3*8` overflows uint32 at `w >= 178956971`

**Batch 2 (lines 204–205)**: `sprintf(thing, "B&W version of %s", argv[optind])` — `thing` is `char[1024]`, format string is 15 chars + filename. Linux PATH_MAX = 4096, so a filename ≥ 1009 bytes causes stack buffer overflow. No bounds check.

## VULN: Heap OOB Read+Write via Zero-Size inbuf/outbuf Allocation in compresspalette (PALETTE photometric)
- **漏洞类别**: memory-safety
- **函数**: main() → compresspalette()
- **行号**: 207, 230-236
- **CWE**: CWE-122 (Heap-Based Buffer Overflow) / CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2bw main() → TIFFOpen() → TIFFReadDirectory() [sets tif_scanlinesize=0 via TIFFScanlineSize overflow] → main() _TIFFmalloc(TIFFScanlineSize(in)=0) [allocates 0 bytes] → TIFFReadScanline() [writes 0 bytes, returns success] → compresspalette(outbuf, inbuf, w, ...) [loops w times over 0-byte allocations]
- **描述**: `TIFFScanlineSize(in)` 内部调用 `multiply(w, 1)` 再 `multiply(result, 8)` 计算扫描线字节数；当 `w >= 536870912`（2^29）时 `w*8` 在 uint32 内溢出并被检测到，`multiply` 返回 0，`TIFFScanlineSize` 返回 0（类型 tsize_t=int32）。tiff2bw.c 第 230 行随即调用 `_TIFFmalloc(0)`，Linux 的 glibc `malloc(0)` 返回非 NULL 的 0 字节分配。第 207 行 `outbuf` 同样因 `TIFFScanlineSize(out)=0` 得到 0 字节分配。`TIFFReadScanline` 以 `tif_scanlinesize=0` 成功返回（写入 0 字节）后，`compresspalette(outbuf, inbuf, w, ...)` 循环 `w`（>= 536870912）次：每次从 0 字节的 `inbuf` 读取 1 字节（`*data++`），并向 0 字节的 `outbuf` 写入 1 字节（`*out++ = v>>8`），导致堆越界读写，破坏相邻堆元数据和对象。
- **触发条件**: 构造 PHOTOMETRIC_PALETTE、BITSPERSAMPLE=8、SAMPLESPERPIXEL=1、ImageWidth >= 536870912 的 TIFF 文件，StripByteCounts=0（确保 TIFFReadScanline 以 0 字节成功返回）。
- **安全影响**: 堆元数据和相邻对象被大量覆写（写入量等于 w 字节，最大约 4GB），攻击者可能通过堆风水精心布局实现任意代码执行（RCE）；同时读取超出分配范围的堆数据构成信息泄露。

## VULN: Heap OOB Read via Zero-Size inbuf Allocation in compresscontig (RGB CONTIG, Lower Threshold)
- **漏洞类别**: memory-safety
- **函数**: main() → compresscontig()
- **行号**: 207, 240-244
- **CWE**: CWE-125 (Out-of-Bounds Read) / CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2bw main() → TIFFOpen() → TIFFReadDirectory() [sets tif_scanlinesize=0] → main() _TIFFmalloc(TIFFScanlineSize(in)=0) → TIFFReadScanline() [writes 0 bytes] → compresscontig(outbuf, inbuf, w)
- **描述**: 对于 PHOTOMETRIC_RGB、PLANARCONFIG_CONTIG（samplesperpixel=3），`TIFFScanlineSize` 的计算路径为：`multiply(w, 3)` = `w*3`，再 `TIFFhowmany8(multiply(w*3, 8))`。当 `w >= 178956971`（约 1.79 亿）时，`w*3*8 = w*24 > UINT32_MAX`，multiply 返回 0，`TIFFScanlineSize(in)=0`。第 240 行 `inbuf = _TIFFmalloc(0)` 获得 0 字节分配。当 `178956971 <= w < 536870912` 时，`outbuf = _TIFFmalloc(w)` 为有效分配；此后 `compresscontig(outbuf, inbuf, w)` 从 `inbuf`（0 字节分配）读取 `3*w` 字节（`rgb++` 执行 3*w 次），发生堆越界读取，可能读取相邻堆对象数据。当 `w >= 536870912` 时 `outbuf` 也是 0 字节分配，同时发生越界写入。此触发阈值（~1.79 亿）远低于 PALETTE 情形（~5.37 亿），更容易构造。
- **触发条件**: 构造 PHOTOMETRIC_RGB、PLANARCONFIG_CONTIG、BITSPERSAMPLE=8、SAMPLESPERPIXEL=3、ImageWidth >= 178956971 的 TIFF 文件，StripByteCounts=0。
- **安全影响**: 从 0 字节 `inbuf` 起始处越界读取 `3*w` 字节堆内存，可泄露相邻堆对象（包括指针、密钥等敏感数据）；若 `w >= 536870912` 同时越界写入 `outbuf`，可破坏堆结构并可能实现 RCE。

## VULN: Heap OOB Read+Write via Zero-Size inbuf/outbuf Allocation in compresssep (RGB SEPARATE)
- **漏洞类别**: memory-safety
- **函数**: main() → compresssep()
- **行号**: 207, 250-258
- **CWE**: CWE-122 (Heap-Based Buffer Overflow) / CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiff2bw main() → TIFFOpen() → TIFFReadDirectory() [sets tif_scanlinesize=0] → main() rowsize=TIFFScanlineSize(in)=0, _TIFFmalloc(3*0=0) [0字节分配] → TIFFReadScanline() × 3 [写入 0 字节] → compresssep(outbuf, inbuf, inbuf+0, inbuf+0, w)
- **描述**: PHOTOMETRIC_RGB、PLANARCONFIG_SEPARATE（每个 plane 单独存储，samplesperpixel=1 per plane）时，`TIFFScanlineSize(in)` 针对单个平面计算：SEPARATE 分支 `scanline = td->td_imagewidth`，再 `TIFFhowmany8(multiply(w, 8))`；当 `w >= 536870912` 时 `w*8` 溢出，返回 0。第 250-251 行：`rowsize = 0`，`_TIFFmalloc(3*0) = _TIFFmalloc(0)` = 0 字节分配（此处 `3*rowsize` 整数乘法结果为 0，不产生溢出但仍分配 0 字节）。三次 `TIFFReadScanline` 均以 0 字节成功返回。`compresssep(outbuf, inbuf, inbuf+0, inbuf+0, w)` 等价于三个指针均指向同一 0 字节 `inbuf` 起始处，循环 w（>= 536870912）次从中读取并向 0 字节 `outbuf` 写入，发生堆越界读写。
- **触发条件**: 构造 PHOTOMETRIC_RGB、PLANARCONFIG_SEPARATE、BITSPERSAMPLE=8、SAMPLESPERPIXEL=3、ImageWidth >= 536870912 的 TIFF 文件，所有 strip 的 StripByteCounts=0，确保各平面 TIFFReadScanline 以 0 字节成功返回。
- **安全影响**: 与 PALETTE 情形相同：堆越界写入 w 字节覆盖相邻堆结构，堆越界读取可信息泄露，极端情况下可被利用实现 RCE。

## VULN: Stack Buffer Overflow via sprintf with Overly Long Input Filename
- **漏洞类别**: memory-safety
- **函数**: main()
- **行号**: 204
- **CWE**: CWE-121 (Stack-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file path (command-line argument)
- **外部触发路径**: tiff2bw main() → sprintf(thing, "B&W version of %s", argv[optind]) where argv[optind] length >= 1009
- **描述**: 第 124 行声明 `char thing[1024]`；第 204 行 `sprintf(thing, "B&W version of %s", argv[optind])` 使用不安全的 `sprintf`，格式字符串前缀 `"B&W version of "` 为 15 字节，若输入 TIFF 文件路径 `argv[optind]` 长度 >= 1009 字节（含终止符 15+1009+1=1025 > 1024），则 sprintf 写入数据溢出栈上 `thing` 缓冲区，覆盖相邻栈帧数据（包括返回地址、保存寄存器等），构成经典栈溢出。Linux 文件路径最大为 PATH_MAX=4096 字节，完全满足溢出条件。
- **触发条件**: 以长度 >= 1009 字节的文件路径名运行 tiff2bw（如 `tiff2bw $(python3 -c "print('A'*1009, end=''").tif output.tif`），文件可为合法 TIFF（不需要特殊内容）。
- **安全影响**: 覆盖 `main()` 的返回地址和栈帧数据；在没有栈 canary 保护（`-fno-stack-protector`）的编译配置下，或通过绕过 canary 的技术，可实现任意代码执行（RCE）；即使有保护也会触发 crash（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
