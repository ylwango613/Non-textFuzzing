Both vulnerabilities are confirmed. Let me write the final audit report.

## VULN: Heap OOB write in jas_icctxtdesc_input when asclen is zero
- **漏洞类别**: memory-safety
- **函数**: jas_icctxtdesc_input()
- **行号**: 1103-1108
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted JP2/JPEG-2000 image file with embedded ICC profile
- **外部触发路径**: `imginfo -f crafted.jp2` → `jp2_decode()` (jp2_dec.c:298) → `jas_iccprof_createfrombuf(dec->colr->data.colr.iccp, iccplen)` → `jas_iccprof_load()` → tag dispatch → `jas_icctxtdesc_input(attrval, in, cnt)`
- **描述**: 在 `jas_icctxtdesc_input()` 中，`txtdesc->asclen` 从 ICC profile 文件字节流读取（32 位无符号 `jas_iccuint32_t = uint_fast32_t`）。当攻击者将 `asclen` 设为 0 时：（1）`jas_malloc(0)` 在 Linux/glibc 下返回非 NULL 指针，通过 `!()` 空指针检查；（2）`jas_stream_read(in, ascdata, 0)` 返回 0，等于 `JAS_CAST(int, 0)`，通过长度校验；（3）第 1108 行 `txtdesc->ascdata[txtdesc->asclen - 1] = '\0'`，由于 `asclen` 为无符号 0，`0 - 1` 下溢为 `UINT_FAST32_MAX`（64 位系统为 `0xFFFFFFFFFFFFFFFF`），在 `ascdata` 起始地址之后极远处写入一字节 `\0`，造成非法内存访问/堆缓冲区越界写。
- **触发条件**: 构造 JP2 文件，COLR box 使用 `method=JP2_COLR_ICC`，嵌入一个 ICC profile，其中含有 TXTDESC 类型标签（如 `JAS_ICC_TAG_PROFDESC`），将标签数据中第 8–12 字节（`asclen` 字段）设为 `0x00000000`，其余字段合法以使代码执行到第 1108 行。
- **安全影响**: 访问地址 `ascdata + UINT_FAST32_MAX` 导致 SIGSEGV（拒绝服务）；若能通过内存映射找到有效可写区域（理论上极为困难），可能实现任意内存写，进而 RCE。主要现实影响：可靠触发崩溃（DoS）。

## VULN: Heap buffer underwrite in jas_icctxt_input when cnt is zero
- **漏洞类别**: memory-safety
- **函数**: jas_icctxt_input()
- **行号**: 1214-1218
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted JP2/JPEG-2000 image file with embedded ICC profile
- **外部触发路径**: `imginfo -f crafted.jp2` → `jp2_decode()` (jp2_dec.c:298) → `jas_iccprof_createfrombuf(dec->colr->data.colr.iccp, iccplen)` → `jas_iccprof_load()` (jas_icc.c:341, `len = tagtabent->len - 8`) → tag dispatch → `jas_icctxt_input(attrval, in, cnt=0)`
- **描述**: 在 `jas_iccprof_load()` 中，变量 `len`（类型 `int`）被赋值为 `tagtabent->len - 8`（无符号减法结果），当 `tagtabent->len == 8`（文件控制）时 `len = 0`，随后作为 `cnt` 传入 `jas_icctxt_input()`。函数内：（1）`jas_malloc(0)` 在 Linux/glibc 下返回非 NULL，通过 `!()` 检查；（2）`jas_stream_read(in, string, 0)` 返回 0 等于 `cnt`，通过长度校验；（3）第 1218 行 `txt->string[cnt - 1] = '\0'`，即 `txt->string[-1] = '\0'`，在 `string` 分配区起始地址**前 1 字节**写入 `\0`，造成堆缓冲区向前越界写（heap underwrite），可破坏 allocator 元数据或相邻堆对象。
- **触发条件**: 构造 JP2 文件，嵌入含有 TXT 类型标签（如 `JAS_ICC_TAG_CPYRT`，type = `JAS_ICC_TYPE_TXT`）的 ICC profile，将该标签在 tag table 中的 `len` 字段设为 8（表示无数据字节，仅含 8 字节头部），使 `cnt = 8 - 8 = 0`。
- **安全影响**: 向 `txt->string[-1]` 写入 1 字节 `\0`，破坏 glibc malloc chunk header 或相邻堆数据，可导致后续 free/malloc 时堆内存损坏，可能被精心利用以实现 RCE；最低影响为程序崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
