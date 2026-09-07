## VULN: Signed Integer Overflow in numprcs Leads to Heap OOB Read/Write
- **漏洞类别**: memory-safety
- **函数**: jpc_dec_tileinit() / jpc_pi_nextrpcl() / jpc_pi_nextpcrl() / jpc_pi_nextcprl() / jpc_dec_decodepkt()
- **行号**: jpc_dec.c:773-777 (溢出), jpc_dec.c:841 (欠分配), jpc_t2dec.c:506 (欠分配), jpc_t2cod.c:303/404/498 (越界计算), jpc_t2cod.c:309/409/503 + jpc_t2dec.c:244,377 (越界访问)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted JP2/JPEG-2000 image file
- **外部触发路径**: `imginfo -f evil.jp2` → `jas_image_decode()` → `jpc_decode()` → `jpc_dec_process_siz()` → `jpc_dec_tileinit()` [jpc_dec.c:777: numprcs溢出 + jpc_dec.c:841: band->prcs欠分配 + jpc_t2dec.c:506: prclyrnos欠分配] → `jpc_dec_decodepkts()` → `jpc_pi_next()` → `jpc_pi_nextrpcl/nextpcrl/nextcprl()` [jpc_t2cod.c:303/404/498: prcno由numhprcs计算超出numprcs, jpc_t2cod.c:309: `++(*prclyrno)` 堆越界写] → `jpc_dec_decodepkt()` [jpc_t2dec.c:244,377: `band->prcs[prcno]` 堆越界读]
- **描述**: 在 `jpc_dec_tileinit()`（jpc_dec.c:777）中，`rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs`，两个操作数均为 `int` 型。当 SIZ marker 设置超大单 tile（如 65537×65537）且 COD marker 将显式 precinct size 指数设为 0（每 precinct 覆盖 1×1 像素）时，`numhprcs = numvprcs = 65537`，乘积 `65537²=4295098369 > INT_MAX`，产生有符号整数溢出，`numprcs` 被截断为 `131073`（小正数）。随后 `jas_alloc2(131073, sizeof(jpc_dec_prc_t))` 分配严重不足的 `band->prcs` 缓冲区，`jas_alloc2(131073, sizeof(long))` 分配 `pirlvl->prclyrnos`。然而 `pirlvl->numhprcs` 保存真实值 65537。在 RPCL/PCRL/CPRL 渐进顺序中，`prcno = prcvind * 65537 + prchind`；当 `prcvind=2, prchind=0` 时 `prcno=131074 ≥ 131073`，造成 `pirlvl->prclyrnos[prcno]` 越界写（`++(*prclyrno)`）和 `band->prcs[prcno]` 越界读。
- **触发条件**: (1) SIZ marker: Xsiz=Ysiz=XTsiz=YTsiz=65537（单 tile，一个分量）；(2) COD marker: Scod=0x01（显式 precinct size），progression order = PCRL/RPCL/CPRL（0x03/0x02/0x04），numrlvls=1，precinct size 字节=0x00（prcwidthexpn=prcheightexpn=0）；(3) 构造至少 2 行 precinct 行的有效 tile-part 数据以触发 prcvind≥2。发布版本（NDEBUG）中 assert 被关闭，OOB 直接执行。
- **安全影响**: 攻击者可控的 `prcno` 偏移使堆越界写入相对 `pirlvl->prclyrnos` 分配基址之后的任意位置，可覆盖 heap metadata 或其他对象指针，具备完整 RCE 潜力；越界读 `band->prcs[prcno]` 可泄露堆地址，辅助 ASLR 绕过。完整攻击链为：提供恶意 JP2 文件 → 受害者或服务端调用 `imginfo`/libjasper → 堆溢出 → 代码执行。

<!-- AUDIT_PROMPT_VERSION: 1 -->
