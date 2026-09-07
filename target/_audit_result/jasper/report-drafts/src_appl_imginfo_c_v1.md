### CVE-Candidate: Signed Integer Overflow in `jpc_dec_tileinit()` Leads to Heap OOB Read/Write (JasPer `imginfo`)

| Field | Value |
|---|---|
| **Severity** | High |
| **CWE** | CWE-190 → CWE-122 (Integer Overflow → Heap-based Buffer Overflow) |
| **CVSS v3.1** | `CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H` → **8.8** |
| **Affected Component** | JasPer `imginfo` / libjasper |
| **Affected Files** | `jpc_dec.c`, `jpc_t2dec.c`, `jpc_t2cod.c` |
| **PoC Status** | **VERIFIED\_CRASH** (PoC #001) |

---

#### 漏洞描述（中文）

在 `jpc_dec_tileinit()`（`jpc_dec.c:777`）中，`rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs` 对两个 `int` 值执行乘法，当 SIZ marker 将 tile 尺寸设为 65537×65537 且 COD marker 将 precinct size 指数设为 0 时，乘积 4,295,098,369 超过 `INT_MAX`，触发有符号整数溢出，`numprcs` 被截断为 131,073，导致 `band->prcs` 与 `prclyrnos` 严重欠分配。后续 RPCL/PCRL/CPRL 渐进遍历中，`prcno` 由真实维度（65,537）计算，当 `prcvind ≥ 2` 时 `prcno ≥ 131,074`，分别造成 `pirlvl->prclyrnos[prcno]` 堆越界写（`++(*prclyrno)`）及 `band->prcs[prcno]` 堆越界读，可覆盖堆元数据或对象指针，具备完整 RCE 潜力；越界读还可泄露堆地址以辅助 ASLR 绕过。

#### Vulnerability Description (English)

In `jpc_dec_tileinit()` (`jpc_dec.c:777`), the expression `rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs` performs signed 32-bit multiplication. A crafted JP2 file with a single 65537×65537 tile and a precinct size exponent of 0 causes the product (4,295,098,369) to overflow `INT_MAX`, truncating `numprcs` to 131,073. Subsequent heap allocations for `band->prcs` and `prclyrnos` are severely undersized. During RPCL/PCRL/CPRL progression, `prcno` is derived from the true dimension (65,537); once `prcvind ≥ 2`, `prcno ≥ 131,074` produces an out-of-bounds write to `prclyrnos` and an out-of-bounds read from `band->prcs`, enabling heap metadata corruption (RCE) and heap address disclosure (ASLR bypass).

---

#### 触发方式 / Trigger

```bash
# Construct a malicious JP2 with:
#   SIZ: Xsiz=Ysiz=XTsiz=YTsiz=65537, 1 component
#   COD: Scod=0x01 (explicit precinct), order=PCRL(0x03), numrlvls=1, prcsize byte=0x00

imginfo -f evil.jp2
```

**Call chain:**
```
imginfo → jas_image_decode() → jpc_decode() → jpc_dec_process_siz()
  → jpc_dec_tileinit()          [jpc_dec.c:777   — numprcs overflow]
                                [jpc_dec.c:841   — band->prcs underalloc]
                                [jpc_t2dec.c:506 — prclyrnos underalloc]
  → jpc_dec_decodepkts() → jpc_pi_next() → jpc_pi_nextpcrl()
                                [jpc_t2cod.c:404/498 — prcno > numprcs]
                                [jpc_t2cod.c:409 — ++(*prclyrno) OOB write]
  → jpc_dec_decodepkt()         [jpc_t2dec.c:244,377 — band->prcs[prcno] OOB read]
```

---

#### PoC 验证状态 / PoC Verification Status

| Item | Detail |
|---|---|
| **Status** | `VERIFIED_CRASH` |
| **PoC ID** | `#001` |
| **PoC Path** | `/data/ylwang/non-textfuzz/target/_poc/jasper/src_appl_imginfo_c/` |
| **Crash Type** | Heap OOB write → process crash / memory corruption |
| **Build Condition** | Release build (`NDEBUG`); assertions suppressed, OOB executes unconditionally |
