Both vulnerabilities confirmed. Here is the final audit report.

## VULN: Heap Buffer Over-read in jp2_decode() CDEF Channel Loop
- **漏洞类别**: memory-safety
- **函数**: jp2_decode()
- **行号**: jp2_dec.c:402-413
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted JP2/JPEG-2000 image file
- **外部触发路径**: imginfo -f evil.jp2 → jp2_decode() → jp2_box_get()(解析 CMAP/CDEF box) → jp2_decode():402 CDEF 循环 → 越界读取 cdef->ents[]
- **描述**: `jp2_decode()` 在 402-413 行用 `dec->numchans` 作为循环上界迭代访问 `dec->cdef->data.cdef.ents[i]`，而 `ents[]` 数组在 `jp2_cdef_getdata()` 中仅分配了 `cdef->numchans`（取自 CDEF box 的 2 字节字段）个条目。`dec->numchans` 在第 329-330 行被设置为 CMAP box 的 `numchans` 值（或图像分量数）。代码在两处值之间没有进行任何大小比对检查：若 `dec->numchans > cdef->numchans`，循环会对 `ents[]` 末端以外的堆内存执行越界读取（每次读取 `jp2_cdefchan_t` = channo/type/assoc 三个 uint_fast16_t 字段），并将读取到的 `channo` 经校验后传递给 `dec->chantocmptlut[channo]` 以及 `jp2_getct()` 参数，使 OOB 数据流入后续图像分量类型设置逻辑。
- **触发条件**: 构造一个 JP2 文件，其中 CMAP box 将 `numchans` 设置为大于 CDEF box 中声明的通道数的值（例如 CMAP numchans=100，CDEF numchans=1，CDEF box 中只有 1 个有效条目），同时附上一个合法的 JPC 码流
- **安全影响**: 堆越界读取导致相邻堆内存泄露（信息泄露）；若 OOB 读出的 channo 值通过 `< dec->numchans` 校验，则该值作为索引访问 `dec->chantocmptlut` 并传入 `jas_image_setcmpttype`，在特定堆布局下可进一步影响控制流；最坏情况下可读取进程堆中的敏感数据或导致崩溃（DoS）

## VULN: Heap Buffer Over-read in jp2_decode() BPCC bpcs Array
- **漏洞类别**: memory-safety
- **函数**: jp2_decode()
- **行号**: jp2_dec.c:275-280
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)
- **严重程度**: Medium
- **攻击向量**: crafted JP2/JPEG-2000 image file
- **外部触发路径**: imginfo -f evil.jp2 → jp2_decode() → jpc_decode()（返回具有不同精度分量的图像）+ jp2_bpcc_getdata()（BPCC box 数据量少于实际分量数）→ jp2_decode():274-280 越界读取 bpcc->bpcs[]
- **描述**: `jp2_bpcc_getdata()` 中 `bpcc->numcmpts = box->datalen`（即 BPCC box 数据区字节数，攻击者完全控制），并据此分配 `bpcc->bpcs`。当 BPCC box 的组件数与 JPC 码流中的实际图像组件数不一致时，第 268-270 行仅打印 "warning" 而不终止（不 goto error）。若 `!samedtype`（JPC 码流中不同分量精度不同），代码在第 275-280 行以 `jas_image_numcmpts(dec->image)` 为上界循环访问 `dec->bpcc->data.bpcc.bpcs[i]`；当 `jas_image_numcmpts > bpcc->numcmpts` 时，循环会越界读取 `bpcs` 数组末端以外的堆字节，读出的字节值被传入 `JP2_BPCTODTYPE()` 宏并与图像分量 dtype 比对。
- **触发条件**: 构造一个 JP2 文件：① JPC 码流中包含至少 2 个具有不同位精度的分量（如分量 0 精度 8、分量 1 精度 10），使 `samedtype` 计算结果为 false；② BPCC box 的 box 长度只声明 1 字节数据（`bpcc->numcmpts = 1`），但 JPC 码流报告 3 个分量
- **安全影响**: 堆越界读取相邻堆内存字节，导致信息泄露；在 ASLR 绕过或堆喷射场景下可能泄露关键地址信息

<!-- AUDIT_PROMPT_VERSION: 1 -->
