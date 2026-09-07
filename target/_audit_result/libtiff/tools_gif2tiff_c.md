I now have all the information needed for a complete analysis. Let me verify the key facts one more time:

- `prefix[4096]`, `suffix[4096]`, `stack[4096]` are globals (lines 99-101)
- `avail` increments unconditionally at line 419 with no upper-bound guard
- The raster OOB check at line 361 fires only after a full block, not per-write inside `process()`
- `datasize` is taken raw from the file at line 331 with no range validation

## VULN: Heap Buffer Overflow in LZW Output via Missing Per-Write Bounds Check in process()
- **漏洞类别**: memory-safety
- **函数**: process(), readraster()
- **行号**: 355-364, 426-428
- **CWE**: CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted GIF file
- **外部触发路径**: main() -> convert() -> readgifimage() -> readraster() -> process() -> `do { *(*fill)++ = *--stackp; } while (stackp > stack);`
- **描述**: `raster` 在 `readgifimage()`（第 279 行）被分配为 `width*height + EXTRAFUDGE`（EXTRAFUDGE=128）字节。`readraster()` 在每个 GIF 数据块处理完毕后（外层 `for` 循环的末尾，第 361 行）才做边界检查 `fill >= raster + width*height`，但在此之前对同一数据块内的所有 LZW 码字调用 `process(code, &fill)`，而 `process()` 内部通过 `do { *(*fill)++ = *--stackp; } while (stackp > stack);`（第 426-428 行）向 `*fill` 写入任意多字节，完全没有针对 `raster` 缓冲区末尾的边界检查。攻击者可使最后一个数据块中的某个 LZW 码字解压出远超 128 字节的输出，使 `fill` 超出 `raster + width*height + EXTRAFUDGE`，写入相邻堆内存。
- **触发条件**: 构造一个宽×高极小（如 1×1）的 GIF，使 raster 只剩极少剩余空间，然后在最后一个 LZW 数据块中放置一个指向长链的符号（利用已建立的 prefix 链），使 `process()` 单次调用写出数百乃至数千字节。
- **安全影响**: 堆上任意写，可覆盖相邻堆块的元数据或对象指针，最坏情况下导致远程/本地代码执行（RCE）；至少可导致进程崩溃（DoS）。

## VULN: Global BSS OOB Write in readraster() via Unvalidated datasize Causes Init Loop Overflow
- **漏洞类别**: memory-safety
- **函数**: readraster()
- **行号**: 331-341
- **CWE**: CWE-787 (Out-of-Bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted GIF file
- **外部触发路径**: main() -> convert() -> readgifimage() -> readraster()：第 331 行 `datasize = getc(infile);`，第 332 行 `clear = 1 << datasize;`，第 338-341 行初始化循环
- **描述**: `datasize` 直接取自 GIF 文件字节，无任何范围校验（合法 GIF 规定 2–8，但代码不强制）。当 `datasize >= 13` 时，`clear = 1 << 13 = 8192`，初始化循环 `for (code = 0; code < clear; code++) { prefix[code] = 0; suffix[code] = code; }` 迭代 8192 次。全局数组 `prefix[4096]`（unsigned int，占 16384 字节）和 `suffix[4096]`（unsigned char，占 4096 字节）的有效下标均为 0–4095。当 `code >= 4096` 时，对 `prefix[code]` 和 `suffix[code]` 的写入均越界，顺序覆盖 BSS 段中相邻的全局变量（`suffix`、`stack`、`datasize`、`codesize`、`codemask`、`clear`、`eoi`、`avail`、`oldcode`、`infile` 指针等），造成全局内存段大范围破坏。
- **触发条件**: 在 GIF 图像数据块前将 LZW minimum code size 字节（GIF 规范中标记为"LZW Minimum Code Size"）设为 13 或更大值（最大 255），即可在程序处理到该帧时触发。
- **安全影响**: BSS 段全局变量大范围任意写，包括 `infile`（FILE* 指针）和 `raster`（unsigned char* 指针），可劫持后续文件 I/O 和内存操作，导致代码执行（RCE）；亦可立即崩溃（DoS）。

## VULN: Global BSS OOB Write in process() via Unbounded avail Exceeding Array Bounds
- **漏洞类别**: memory-safety
- **函数**: process()
- **行号**: 417-419, 421
- **CWE**: CWE-787 (Out-of-Bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted GIF file
- **外部触发路径**: main() -> convert() -> readgifimage() -> readraster() -> process()：第 417 行 `prefix[avail] = oldcode;`，第 418 行 `suffix[avail] = firstchar;`，第 419 行 `avail++;`
- **描述**: 全局变量 `avail` 在 `process()` 中第 419 行无条件自增（`avail++`）。第 421 行的条件 `if (((avail & codemask) == 0) && (avail < 4096))` 仅控制 `codesize` 的增长，并不阻止 `avail` 本身超过 4095。当输入 GIF 包含足够多不重复的 LZW 码字使 `avail` 递增至 4096 时，第 417-418 行对 `prefix[4096]` 和 `suffix[4096]` 的写入越界。之后 `avail` 继续无限递增（4097、4098…），每次调用 `process()` 都继续向 BSS 段写越界数据，覆盖 `suffix[]`、`stack[]` 以及随后的 `datasize`、`infile` 等关键全局变量。此外，越界后的码字查表（第 412 行 `suffix[code]`、第 413 行 `prefix[code]`）也变为 OOB 读。
- **触发条件**: 使用最小 datasize（如 2，clear=4，avail 从 6 起步），在 GIF 数据中提供约 4090 个产生新码字的 LZW 码（不发送 clear 码和 eoi 码），使 `avail` 自然递增至 4096 并继续。无需任何特殊编码技巧，只需足够长的 LZW 数据流。
- **安全影响**: BSS 段越界任意写，可覆盖 `infile` FILE* 指针或 `raster` 指针等敏感全局变量，最坏情况导致代码执行（RCE）；亦可因非法内存访问崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
