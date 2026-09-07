I have completed the full analysis across all 1815 lines of tiffcp.c, traced the complete call chain, verified the buffer allocation path via `_TIFFsetNString` and `checkInkNamesString`, and confirmed the heap bounds. The findings are below.

## VULN: Heap OOB Read via INKNAMES/NUMBEROFINKS Mismatch
- **漏洞类别**: memory-safety
- **函数**: tiffcp()
- **行号**: 720-737
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffcp main() → tiffcp(in, out) → TIFFGetField(TIFFTAG_NUMBEROFINKS) / TIFFGetField(TIFFTAG_INKNAMES) → while(ninks>1) loop → strchr(cp,'\0') / strlen(cp) reading heap OOB → TIFFSetField(out, TIFFTAG_INKNAMES, inflated_inknameslen, inknames) → _TIFFsetNString copies OOB bytes
- **描述**: 在 tiffcp.c 第 727–736 行，代码用 `TIFFTAG_NUMBEROFINKS`（`ninks`，完全来自 TIFF 文件）控制 `while (ninks > 1)` 循环次数，循环内通过 `strchr(cp, '\0')` + `cp++` + `strlen(cp)` 逐一遍历 INKNAMES 缓冲区中的墨水名字符串。但 `td->td_inknames` 缓冲区仅分配了 `td_inknameslen` 字节（由 `_TIFFsetNString` 精确分配，且 `checkInkNamesString` 仅校验 `td_samplesperpixel` 个名字）。当 `ninks > td_samplesperpixel` 时，循环在耗尽合法名字之后继续对 `cp` 调用 `strchr`/`strlen`，扫描超出堆分配块边界的内存（其他堆分配、堆元数据等）。随后以累积的 `inknameslen` 调用 `TIFFSetField(out, TIFFTAG_INKNAMES, inknameslen, inknames)`，该函数内部 `checkInkNamesString` 再次以膨胀后的 `slen` 扫描 `inknames` 指针之外的内存，`_TIFFsetNString` 又通过 `setByteArray` 拷贝 `inknameslen` 字节到输出，造成第二次 OOB 读并将堆内容写入输出 TIFF 文件。
- **触发条件**: 构造 TIFF 文件：设置 `TIFFTAG_SAMPLESPERPIXEL = K`（小值，如 1），`TIFFTAG_INKNAMES` 包含 K 个合法 NUL 终止名字（共 N 字节），`TIFFTAG_NUMBEROFINKS = M`（远大于 K，如 65535）。libtiff 读取时 `checkInkNamesString` 按 K 验证并接受 inknames；tiffcp 的循环则按 M−1 次迭代，K−1 次后即越界。
- **安全影响**: 最坏情况：堆上相邻数据（指针、密钥、路径等）被写入输出 TIFF（信息泄露）；若 `strchr` 扫描至不可读内存页则程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
