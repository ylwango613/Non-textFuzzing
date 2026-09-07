I now have a complete picture. Let me compile the final analysis.

**Findings summary:**

**1. newfilename() OOB write (tiffsplit.c:149-153):** When `argv[2]` is ≥ 8190 chars, `fpnt = fname + strlen(fname)` makes `fpnt[1]` or `fpnt[2]` write beyond the `fname[8192]` global array boundary into adjacent BSS. On the first call, `fpnt[0]='a'`, `fpnt[1]=computed_char`, `fpnt[2]=computed_char` are written unconditionally. With `strlen(argv[2])=8190`, `fpnt[2]` hits `fname[8192]` — one past the last valid index 8191.

**2. Integer overflow in `TIFFReadRawStrip1`/`TIFFReadRawTile1` bounds check (tif_read.c:198, 440):** `toff_t` is `uint32`, `tsize_t` is `int32`. The check `td->td_stripoffset[strip] + size > tif->tif_size` computes `uint32 + int32` in uint32 arithmetic, which wraps when the attacker sets a large `StripOffsets` value. The wrapped result passes the bounds check, then `_TIFFmemcpy(buf, tif->tif_base + large_offset, size)` reads out-of-bounds from the mmap'd file region. Contrast: `TIFFFillStrip()` (lines 309-310) correctly uses a two-comparison pattern; `TIFFReadRawStrip1` was never similarly hardened.

## VULN: tiffsplit newfilename() global buffer out-of-bounds write via long prefix argument
- **漏洞类别**: memory-safety
- **函数**: newfilename()
- **行号**: 109-153
- **CWE**: CWE-787 (Out-of-Bounds Write)
- **CVSS v3.1**: 6.6 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file + long argv[2] prefix
- **外部触发路径**: tiffsplit main() → strncpy(fname, argv[2], 8192) → newfilename() → fpnt = fname + strlen(fname) → fpnt[1]/fpnt[2] write past fname[8192]
- **描述**: `fname` 是 8192 字节的静态全局数组（`static char fname[PATH_LENGTH]`），有效索引为 0–8191。当用户传入长度为 N（N ≥ 8190）的 argv[2] 时，main() 中的 `strncpy(fname, argv[2], sizeof(fname))` 将 fname 填满，`strlen(fname)` 返回 N（最大 8191）。随后 `newfilename()` 计算 `fpnt = fname + strlen(fname)`，并在每次调用时无条件写入 `fpnt[0]`、`fpnt[1]`、`fpnt[2]`。当 `strlen(fname)=8190` 时，`fpnt[2]` 写入 `fname[8192]`——数组末端之后一字节；当 `strlen(fname)=8191` 时，`fpnt[1]` 和 `fpnt[2]` 分别写入 `fname[8192]` 和 `fname[8193]`，均越界。被写入的值为 `'a'`–`'z'` 的小写字母，由 fnum 决定。写入目标为 BSS 段，紧邻 `fname` 的静态变量（如 newfilename() 内的 `fpnt` 指针、`fnum`、`lastTurn` 等）可能被破坏。
- **触发条件**: 攻击者提供：(1) 任意能被 TIFFOpen 成功打开的 TIFF 文件（哪怕只有 1 页）；(2) argv[2]（输出前缀）长度 ≥ 8190 字节。newfilename() 在首次调用（第一页处理之前）就触发越界写入，无需多页 TIFF。
- **安全影响**: 最坏情况下，覆盖 BSS 中相邻的函数指针（如 `fpnt` 指针）可被进一步利用实现任意内存写入；至少会导致程序崩溃（DoS）。

## VULN: TIFFReadRawStrip1/TIFFReadRawTile1 integer overflow in mmap bounds check enabling OOB read
- **漏洞类别**: memory-safety
- **函数**: TIFFReadRawStrip1(), TIFFReadRawTile1()
- **行号**: tif_read.c:198-209 (strips), tif_read.c:440-451 (tiles)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-Bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() (mmap 模式) → tiffcp() → cpStrips() → TIFFReadRawStrip() → TIFFReadRawStrip1(): `td->td_stripoffset[strip] + size > tif->tif_size` 整数回绕 → `_TIFFmemcpy(buf, tif->tif_base + out_of_range_offset, size)` 越界读；cpTiles() 同理经 TIFFReadRawTile() → TIFFReadRawTile1() 触发。
- **描述**: `toff_t` 定义为 `uint32`，`tsize_t` 定义为 `int32`（有符号）。在内存映射（mmap）路径下，`TIFFReadRawStrip1` 和 `TIFFReadRawTile1` 均使用形如 `td->td_stripoffset[strip] + size > tif->tif_size` 的边界检查（其中三个操作数均参与 uint32 算术运算）。当攻击者将 StripOffsets 设为接近 `0xFFFFFFFF` 的值（如 `0xFFFFF000`）、StripByteCounts 设为适当的值（如 `0x1010`）时，两数之和在 uint32 下溢出回绕为一个小值（此例为 `0x10`）；若文件实际大小大于该小值（如 `0x2000` 字节），边界检查 `0x10 > 0x2000` 为假，检查被绕过。随后 `_TIFFmemcpy(buf, tif->tif_base + 0xFFFFF000, 0x1010)` 从 mmap 映射区域（仅 `0x2000` 字节）的 `+0xFFFFF000` 偏移处读取，远超文件映射末端，形成越界读。注意：`TIFFFillStrip()`（行 309-310）已采用不会溢出的双重比较 `bytecount > tif->tif_size || offset > tif->tif_size - bytecount`，但 `TIFFReadRawStrip1` 始终未做同样修正。
- **触发条件**: 攻击者构造一个 TIFF 文件，将 TIFFTAG_STRIPOFFSETS（或 TIFFTAG_TILEOFFSETS）某个条目设为接近 `0xFFFFFFFF` 的大值，将对应的 TIFFTAG_STRIPBYTECOUNTS（或 TIFFTAG_TILEBYTECOUNTS）设为合适的小值使两数之和在 uint32 下回绕，且实际文件大小大于回绕后的值（确保通过检查）。运行 tiffsplit 处理该文件，并启用 mmap 支持（HAVE_MMAP，这是 Linux 系统默认编译选项）。
- **安全影响**: 轻则程序访问 mmap 区域之外的未映射内存，触发 SIGSEGV 崩溃（可靠 DoS）；重则若 `tif_base + large_offset` 恰好指向进程地址空间中已映射的堆/栈/其他 mmap 区域，则将最多 `StripByteCount` 字节的进程内存内容（堆数据、指针、敏感信息）复制到 `buf` 并写入输出 TIFF 文件，造成高危信息泄露。

<!-- AUDIT_PROMPT_VERSION: 1 -->
