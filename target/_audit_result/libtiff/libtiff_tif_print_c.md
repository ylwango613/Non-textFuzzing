I've completed the full analysis of tif_print.c. Let me produce the final audit report.

## VULN: Heap OOB Read in TIFFPrintDirectory via Out-of-Order COLORMAP/BITSPERSAMPLE IFD Tags
- **漏洞类别**: memory-safety
- **函数**: TIFFPrintDirectory()
- **行号**: 464-470
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: `tiffinfo -c crafted.tif` → `TIFFOpen()` → `TIFFReadDirectory()` (processes COLORMAP before BITSPERSAMPLE due to out-of-order IFD) → `TIFFPrintDirectory(tif, stdout, TIFFPRINT_COLORMAP)` → color-map print loop at tif_print.c:464-470
- **描述**: 在 `TIFFReadDirectory` 的第二轮 IFD 标签处理循环中（tif_dirread.c），`TIFFTAG_BITSPERSAMPLE`（tag 0x0102 = 258）并没有像 `TIFFTAG_SAMPLESPERPIXEL` 那样被预先提取；两者均在文件中出现的顺序处理。若攻击者构造一个 IFD 使 `TIFFTAG_COLORMAP`（tag 0x0140 = 320）出现在 `TIFFTAG_BITSPERSAMPLE` 之前，此时 `td_bitspersample` 仍为默认值 1，因此 `td_colormap[0/1/2]` 各被 `_TIFFsetShortArray` 分配了 `1<<1 = 2` 个 uint16 元素（共 4 字节/通道）。随后 `TIFFTAG_BITSPERSAMPLE` 被处理并将 `td_bitspersample` 设为攻击者选定的值（如 16）。当 `TIFFPrintDirectory` 以 `TIFFPRINT_COLORMAP` 标志运行时，第 464 行计算 `n = 1L << td->td_bitspersample = 65536`，循环在第 468–470 行依次访问 `td_colormap[0][l]`、`td_colormap[1][l]`、`td_colormap[2][l]`（l 从 0 到 65535），而每个数组仅有 2 个有效 uint16，造成最多约 131064 字节的堆越界读取。
- **触发条件**: 构造一个 TIFF 文件，其 IFD 将 `COLORMAP` 标签（count = 6，满足 CheckDirCount(3\*2=6) 的校验，包含 6 个 uint16 数据值）置于 `BITSPERSAMPLE` 标签（value = 16）之前（乱序 IFD），然后以 `-c` 选项运行 `tiffinfo`。
- **安全影响**: 进程堆内存越界读取，读取范围可达数十万字节；可造成进程崩溃（DoS）或通过 fprintf 将堆内敏感数据（如指针、密钥材料）输出到 stdout，导致信息泄露。

## VULN: Heap OOB Read in TIFFPrintDirectory via Out-of-Order TRANSFERFUNCTION/BITSPERSAMPLE IFD Tags
- **漏洞类别**: memory-safety
- **函数**: TIFFPrintDirectory()
- **行号**: 478-481
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: `tiffinfo -c crafted.tif` → `TIFFOpen()` → `TIFFReadDirectory()` (processes TRANSFERFUNCTION before BITSPERSAMPLE) → `TIFFPrintDirectory(tif, stdout, TIFFPRINT_COLORMAP|TIFFPRINT_CURVES)` → transfer-function print loop at tif_print.c:478-481
- **描述**: 与 COLORMAP 漏洞机制完全相同。`TIFFTAG_TRANSFERFUNCTION`（tag 0x012D = 301）在 IFD 中出现于 `TIFFTAG_BITSPERSAMPLE`（tag 0x0102 = 258）之前时，`tif_dirread.c` 第二轮循环以 `td_bitspersample=1`（默认值）处理 TRANSFERFUNCTION；`_TIFFsetShortArray` 为 `td_transferfunction[0]`（以及可能的 `[1]`、`[2]`）各分配 `1<<1 = 2` 个 uint16 元素（4 字节/通道）。随后 BITSPERSAMPLE 被设为 16。`TIFFPrintDirectory` 在 `TIFFPRINT_CURVES` 标志下，第 478 行计算 `n = 1L<<16 = 65536`，第 481 行在循环中访问 `td_transferfunction[0][l]`（l 从 0 到 65535），造成最多约 131064 字节的堆越界读取。
- **触发条件**: 构造一个 TIFF 文件，IFD 中 `TRANSFERFUNCTION` 标签（count = 2，即 `1<<1` 个条目，满足 `tdir_count == v` 条件，绕过 CheckDirCount）出现在 `BITSPERSAMPLE`（value = 16）标签之前（乱序 IFD），然后以 `-c` 选项运行 `tiffinfo`。
- **安全影响**: 进程堆内存越界读取，导致进程崩溃（DoS）或通过 fprintf 将堆内敏感数据输出到 stdout，造成信息泄露。

## VULN: NULL Pointer Dereference in TIFFPrintDirectory Transfer Function Print via Out-of-Order EXTRASAMPLES/TRANSFERFUNCTION IFD Tags
- **漏洞类别**: memory-safety
- **函数**: TIFFPrintDirectory()
- **行号**: 482-484
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 5.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: `tiffinfo -c crafted.tif` → `TIFFOpen()` → `TIFFReadDirectory()` (processes EXTRASAMPLES before TRANSFERFUNCTION in out-of-order IFD) → `TIFFPrintDirectory(tif, stdout, TIFFPRINT_CURVES)` → inner loop at tif_print.c:482-484 dereferences NULL `td_transferfunction[i]`
- **描述**: 在 `tif_dir.c` 的 `TIFFTAG_TRANSFERFUNCTION` 设置逻辑中（行 377），决定分配几条传输函数数组的变量 `v` 由 `(td->td_samplesperpixel - td->td_extrasamples) > 1 ? 3 : 1` 决定。`TIFFTAG_SAMPLESPERPIXEL`（tag 277）会被预先提取，但 `TIFFTAG_EXTRASAMPLES`（tag 338 = 0x0152）和 `TIFFTAG_TRANSFERFUNCTION`（tag 301 = 0x012D）在第二轮按文件中出现顺序处理。若攻击者将乱序 IFD 构造成 EXTRASAMPLES（tag 338，高于 TRANSFERFUNCTION tag 301）先于 TRANSFERFUNCTION 出现，则：EXTRASAMPLES 设置 `td_extrasamples=2`；随后 TRANSFERFUNCTION 处理时 `v = (3-2)>1 ? 3:1 = 1`，仅分配 `td_transferfunction[0]`，`td_transferfunction[1]` 和 `td_transferfunction[2]` 保持 `TIFFDefaultDirectory` 时 `_TIFFmemset(td, 0, sizeof(*td))` 初始化的 NULL 值。在 `TIFFPrintDirectory` 第 482 行，内层循环 `for (i=1; i < td->td_samplesperpixel; i++)` 将 `i` 取到 1 和 2，第 484 行对 `td->td_transferfunction[1][l]` 进行解引用，相当于对 NULL 指针加偏移后解引用，必然触发 SIGSEGV 并使进程崩溃。
- **触发条件**: 构造一个 TIFF 文件，`SAMPLESPERPIXEL=3`，IFD 乱序中 `EXTRASAMPLES`（count=2）出现在 `TRANSFERFUNCTION` 之前，`TRANSFERFUNCTION` tag 数据合法（count=2，即单张 `1<<bitspersample` 条目），然后以 `-c` 选项运行 `tiffinfo`。
- **安全影响**: 进程以 SIGSEGV 崩溃，造成可靠的拒绝服务（DoS）；在开启了 ASLR 的系统上不可直接利用为代码执行。

<!-- AUDIT_PROMPT_VERSION: 1 -->
