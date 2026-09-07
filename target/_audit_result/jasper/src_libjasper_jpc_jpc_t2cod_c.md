Now I have all the information needed to produce my findings. Let me compile the analysis.

**Batch 1 findings (lines 1-220):** `jpc_pi_nextlrcp` and `jpc_pi_nextrlcp` — loop-resume via `goto skip` is logically consistent; `prcno` is bounded by the inner `for` condition `prcno < numprcs`, safe.

**Batch 2 findings (lines 222-522):** Three functions — `jpc_pi_nextrpcl` (L302-303), `jpc_pi_nextpcrl` (L403-404), `jpc_pi_nextcprl` (L497-498) — compute `prcno = prcvind * pi->pirlvl->numhprcs + prchind` (both `int`). Only guard is `assert(prcno < numprcs)`, compiled away in release builds.

**Root cause chain confirmed:**
- `jpc_dec.c:777`: `rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs` — signed 32-bit product with **no overflow check**.
- `jpc_t2dec.c:505-510`: `pirlvl->numprcs` receives the overflowed small value; `pirlvl->numhprcs` receives the original large value. `prclyrnos` is allocated with the small `numprcs`.
- `jpc_t2cod.c:302,308` / `403,408` / `497,503`: iterator computes `prcno` using the large `numhprcs`, bypasses the release-build disabled `assert`, then writes via `++(*prclyrno)` at `prclyrnos[prcno]` — **heap OOB write**.
- `prcwidthexpn = 0` is parsed from file (4-bit `parwidthval & 0xf`) with **no lower-bound validation** in `jpc_cs.c`.
- Concrete trigger: a 5 × 858 993 460 JPEG-2000 tile with `prcwidthexpn = prcheightexpn = 0` gives `numhprcs = 5`, `numvprcs = 858993460`, `numprcs = 5 × 858993460 mod 2^32 = 4` (overflowed) while `numhprcs` stays 5; tile pixel data (~17 GB with `int_fast32_t`) requires sufficient system memory but `jas_matrix_create` uses `jas_safe_size_mul` so allocation on a well-resourced system proceeds.

**Batch 3 findings (lines 522-708):** `jpc_pchglist_insert` grows with `+128` increments using `jas_realloc2` (overflow-safe). `jpc_pi_create0`, `jpc_pi_init`, `jpc_pi_destroy` — no issues.

## VULN: Signed Integer Overflow in numprcs Leads to prclyrnos Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: jpc_pi_nextrpcl(), jpc_pi_nextpcrl(), jpc_pi_nextcprl()
- **行号**: 302-310, 403-412, 497-510
- **CWE**: CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted JPEG-2000 image file
- **外部触发路径**: imginfo -f evil.jp2 → jas_image_decode() → jpc_decode() → jpc_dec_tiledecode() → jpc_dec_tileinit() [rlvl->numprcs overflows at jpc_dec.c:777] → jpc_t2dec_decode() → jpc_pi_nextrpcl/nextpcrl/nextcprl() → prclyrnos[prcno] OOB write at jpc_t2cod.c:308/408/503
- **描述**: 在 `jpc_dec.c:777`，`rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs` 以两个 `int` 相乘，无溢出检查。当攻击者构造使乘积超过 `INT_MAX` 的 tile（如宽 5、高 858 993 460，且 `prcwidthexpn = prcheightexpn = 0`），`numprcs` 回绕为小正值（此例为 4），而 `numhprcs` 保持真实值 5。`jpc_t2dec.c:506` 据此小值为 `prclyrnos` 分配内存（仅 4 个槽位）。之后在三个迭代器函数中，`pi->prcno = prcvind * pi->pirlvl->numhprcs + prchind`（第 302/403/497 行）用真实的大 `numhprcs=5` 计算，`prcvind≥1` 时 `prcno≥5` 超出分配范围；Release 编译下唯一的防护 `assert(prcno < numprcs)`（第 304/405/499 行）被编译器消除，随即 `++(*prclyrno)` 在第 310/411/505 行对越界地址执行写操作，造成堆内存破坏。`prcwidthexpn` 来自 COD marker 4-bit 字段，`jpc_cs.c` 仅读取但不校验其下界（允许为 0），是该路径的使能条件。
- **触发条件**: 攻击者构造一个 JPEG-2000 文件：(1) COD marker 中 `parwidthval = parheightval = 0`（即 `prcwidthexpn = prcheightexpn = 0`）；(2) tile 尺寸满足 `numhprcs × numvprcs` 产生 int32 溢出但 tile 仍可被分配（如 5 像素宽 × 858 993 460 像素高）；(3) 使用 RPCL/PCRL/CPRL 进展顺序（POC/COD 中指定）。在内存充足（≥16 GB 可用）的系统上 tile 像素数据可成功分配，解码流程继续至报文迭代器。
- **安全影响**: 堆越界写（写入 `prclyrnos` 分配区域之后的堆元数据或相邻对象），攻击者可借此实现任意代码执行（RCE）；在利用失败时至少触发进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
