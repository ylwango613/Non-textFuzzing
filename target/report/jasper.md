# jasper (imginfo) Vulnerabilities

<!-- REPORT_SOURCE: src_appl_imginfo_c_v1 -->
<!-- DEDUP: jpc_dec_tileinit::CWE-190 -->
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

<!-- REPORT_SOURCE: src_libjasper_base_jas_icc_c_v2 -->
<!-- DEDUP: jas_icctxt_input::CWE-787 -->
### Heap Buffer Underwrite in `jas_icctxt_input` When `cnt` Is Zero (JasPer imginfo)

| 字段 | 值 |
|------|-----|
| **Severity** | High |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **CVSS v3.1** | 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Component** | `jas_icctxt_input()` — `src/libjasper/base/jas_icc.c:1218` |

---

#### 漏洞描述 / Description

**中文**：当 JP2 文件嵌入的 ICC profile 中某 TXT 类型标签的 `len` 字段被设为 8 时，`jas_iccprof_load()` 计算得 `cnt = 0` 并传入 `jas_icctxt_input()`。该函数调用 `jas_malloc(0)` 获得非 NULL 指针后，在第 1218 行执行 `txt->string[cnt - 1] = '\0'`，即对 `txt->string[-1]` 写入一字节 `\0`，造成堆缓冲区向前越界写（heap underwrite），可破坏 glibc allocator 元数据或相邻堆对象，最终可能导致崩溃或被利用实现远程代码执行。

**English**: When a crafted JP2 file contains an ICC profile TXT-type tag with `len` set to 8, `jas_iccprof_load()` derives `cnt = 0` and passes it to `jas_icctxt_input()`. After `jas_malloc(0)` returns a non-NULL pointer, line 1218 writes `'\0'` to `txt->string[-1]`—one byte *before* the allocation boundary—corrupting glibc heap metadata or adjacent heap objects, with potential for crash (DoS) or exploitation leading to RCE.

---

#### 触发方式 / Trigger

```bash
# 构造含 len=8 TXT ICC 标签的 JP2 文件后执行：
imginfo -f crafted.jp2
```

调用链：`imginfo` → `jp2_decode()` → `jas_iccprof_createfrombuf()` → `jas_iccprof_load()` (`cnt=0`) → `jas_icctxt_input(attrval, in, 0)`

---

#### PoC 验证状态 / PoC Status

| 项目 | 内容 |
|------|------|
| **状态** | ✅ `VERIFIED_CRASH` |
| **PoC 编号** | 002 |
| **PoC 路径** | `/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_icc_c` |

<!-- REPORT_SOURCE: src_libjasper_base_jas_icc_c_v1 -->
<!-- DEDUP: jas_icctxtdesc_input::CWE-787 -->
### Heap OOB Write in `jas_icctxtdesc_input()` When `asclen` is Zero (JasPer imginfo)

| 字段 / Field | 值 / Value |
|---|---|
| **严重程度 / Severity** | High |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **CVSS v3.1** | 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **函数 / Function** | `jas_icctxtdesc_input()` |
| **文件 / File** | `src/libjasper/base/jas_icc.c` (L1103–1108) |

---

#### 漏洞描述（中文）

在 `jas_icctxtdesc_input()` 中，`asclen` 字段直接从 ICC profile 字节流读取，未对零值进行边界检查。当攻击者将 `asclen` 设为 `0` 时，第 1108 行的 `txtdesc->ascdata[txtdesc->asclen - 1] = '\0'` 因无符号下溢（`0 - 1 = UINT_FAST32_MAX`）导致在 `ascdata` 起始地址之后约 16 EB 处写入一字节 `\0`，造成堆缓冲区越界写。现实场景中主要引发可靠的进程崩溃（DoS）；若恰好存在可映射可写区域，理论上可升级为任意内存写（RCE）。

#### Vulnerability Description (English)

In `jas_icctxtdesc_input()`, the `asclen` field is read directly from the ICC profile byte stream without validation for zero. When set to `0`, the statement `txtdesc->ascdata[asclen - 1] = '\0'` at line 1108 triggers an unsigned integer underflow (`0 - 1 = UINT_FAST32_MAX`), writing a single null byte roughly 16 EB past the start of the heap allocation — a classic heap out-of-bounds write. The primary real-world impact is a reliable crash (DoS); arbitrary write leading to RCE is theoretically possible but practically infeasible.

---

#### 触发方式 / Trigger

```bash
# 构造含 asclen=0 的 TXTDESC ICC 标签的 JP2 文件后执行：
imginfo -f crafted.jp2
```

**调用链 / Call Chain:**

```
imginfo -f crafted.jp2
  └─ jp2_decode()                          [jp2_dec.c:298]
       └─ jas_iccprof_createfrombuf()
            └─ jas_iccprof_load()
                 └─ jas_icctxtdesc_input() [jas_icc.c:1108]  ← OOB write
```

---

#### PoC 验证状态 / PoC Verification Status

| 项目 | 状态 |
|---|---|
| **验证结果 / Result** | ✅ VERIFIED_CRASH |
| **PoC 路径 / Path** | `/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_base_jas_icc_c/001` |
| **崩溃类型 / Crash Type** | SIGSEGV（非法内存访问 / Illegal memory access） |

<!-- REPORT_SOURCE: src_libjasper_jpc_jpc_dec_c_v2 -->
<!-- DEDUP: jpc_dec_process_siz::CWE-252 -->
### CVE-Candidate: Missing Error Return After `jas_safe_size_add` Overflow in `jpc_dec_process_siz`

| 字段 | 值 |
|------|-----|
| **Severity** | Low |
| **CWE** | CWE-252 (Unchecked Return Value) / CWE-190 (Integer Overflow) |
| **CVSS v3.1** | 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L) |
| **Component** | `src/libjasper/jpc/jpc_dec.c`, `jpc_dec_process_siz()`, lines 1282–1284 |
| **PoC** | `_poc/jasper/src_libjasper_jpc_jpc_dec_c/poc_002` — **VERIFIED\_CRASH** |

---

#### 漏洞描述（Chinese）

在 `jpc_dec_process_siz()` 的样本计数循环中，当 `jas_safe_size_add()` 因 `size_t` 加法溢出返回 `false` 时，代码仅打印错误信息而缺失应有的 `return -1`，导致 `num_samples` 保留溢出前的旧值并继续执行后续逻辑。与之对比，同函数中 `jas_safe_size_mul` 的失败路径（lines 1280–1281）正确地执行了 `return -1`，说明此处属于不一致的错误处理遗漏。在 `max_samples=0`（禁用样本上限）配置下，该缺陷可使精心构造的多组件 JP2 图像绕过累积样本数检测，导致超量内存分配（DoS）。

#### Vulnerability Description (English)

In the sample-count accumulation loop of `jpc_dec_process_siz()`, a missing `return -1` after a `jas_safe_size_add()` overflow failure allows execution to continue with a stale (pre-overflow) `num_samples` value. This contrasts with the adjacent `jas_safe_size_mul` failure path which correctly returns early. Under the `max_samples=0` configuration (limits disabled), a crafted JP2 file with a large number of components can bypass cumulative sample-count enforcement, potentially triggering excessive memory allocation (DoS).

---

#### 触发方式 / Trigger

构造含大量组件（numcomps → 16384）、各组件样本数之和超过 `SIZE_MAX` 的 JP2 文件，然后执行：

```bash
imginfo --max-samples 0 -f crafted.jp2
```

> **注意**：默认配置（`max_samples=64M`）下，单组件即触发超限拦截，漏洞不可利用。仅在显式传入 `--max-samples 0` 时才具备实际危害。

---

#### PoC 验证状态 / PoC Status

```
Status : VERIFIED_CRASH
Path   : _poc/jasper/src_libjasper_jpc_jpc_dec_c/poc_002
```

<!-- REPORT_SOURCE: src_libjasper_jpc_jpc_dec_c_v1 -->
<!-- DEDUP: jpc_dec_tileinit::CWE-758 -->
### CVE-Candidate: UB Negative-Shift → Zero-Size Heap Write in `jpc_dec_tileinit` (JasPer imginfo)

---

**Severity:** Medium | **CWE:** CWE-758 / CWE-122 | **CVSS v3.1:** 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)

---

#### Vulnerability Description / 漏洞描述

**EN:** In JasPer's `jpc_dec_tileinit()`, when a crafted JPEG-2000 file carries a COD/COC marker with the PRT flag set and a precinct width exponent of 0, the expression `cbgwidthexpn = prcwidthexpn - 1 = -1` triggers a C11 undefined behavior negative left-shift. The resulting value is truncated to `uint_fast16_t` (becoming `2^64-1` on 64-bit platforms), causing `numhcblks = numvcblks = 0`, which leads to `jpc_tagtree_create(0, 0)` performing an 8-byte write into a zero-byte heap allocation.

**ZH:** 在 JasPer 的 `jpc_dec_tileinit()` 中，当精心构造的 JPEG-2000 文件的 COD/COC marker 启用 PRT 标志且预制宽度指数（`parwidthval`）为 0 时，计算 `cbgwidthexpn = -1` 后发生 C11 未定义的负数移位行为。该值被截断为 `uint_fast16_t`（64 位平台变为 `2^64-1`），最终导致 `jpc_tagtree_create(0, 0)` 对零字节堆分配执行 8 字节越界写入。调试构建中触发 `assert` 中止，发布构建在 ASAN/jemalloc 严格分配器下被捕获为堆缓冲区溢出，可导致进程崩溃（DoS）。

---

#### Trigger / 触发方式

```bash
# imginfo command-line usage
imginfo -f <crafted.jp2>

# Crafting conditions (COD/COC marker):
#   - Scod/Scoc bit0 (PRT flag) = 1
#   - At least one precinct size byte: low nibble (parwidthval) = 0x0
#   - numdlvls >= 1  (at least one non-LL resolution level)
```

Call path:

```
imginfo
 └─ jpc_decode()
     └─ jpc_dec_decode()
         └─ jpc_dec_process_sod()
             └─ jpc_dec_tileinit()          # line 798: cbgwidthexpn = -1 (UB)
                 └─ jpc_tagtree_create(0,0) # jpc_tagtree.c:159: 8-byte write on 0-byte alloc
```

---

#### PoC Verification Status / PoC 验证状态

| Item | Detail |
|------|--------|
| **Status** | `VERIFIED_CRASH` |
| **PoC ID** | `001` |
| **PoC Path** | `/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_jpc_jpc_dec_c` |
| **Crash Behavior** | Debug build: `assert` abort at `jpc_tagtree.c:109` and `jpc_dec.c:875`; Release + ASAN: heap-buffer-overflow on zero-byte allocation |
| **Impact** | Denial of Service (reliable crash); theoretical heap metadata corruption under specific allocator layouts |

<!-- REPORT_SOURCE: src_libjasper_jpc_jpc_t2cod_c_v1 -->
<!-- DEDUP: jpc_pi_nextrpcl::CWE-787 -->
### CVE-Pending: Signed Integer Overflow in `numprcs` Leads to Heap Out-of-Bounds Write in JasPer `jpc_pi_next*` Iterators

---

**Severity:** High | **CWE:** CWE-787 (Out-of-bounds Write) | **CVSS v3.1:** 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

**Affected Component:** `src/libjasper/jpc/jpc_t2cod.c` — `jpc_pi_nextrpcl()` (L302–310), `jpc_pi_nextpcrl()` (L403–412), `jpc_pi_nextcprl()` (L497–510)

---

#### 漏洞描述（中文）

`jpc_dec.c:777` 中以两个 `int` 直接相乘计算 `rlvl->numprcs = rlvl->numhprcs * rlvl->numvprcs`，缺乏溢出检查；当攻击者构造使乘积超过 `INT_MAX` 的 tile（例如宽 5 像素、高 858 993 460 像素、`prcwidthexpn = prcheightexpn = 0`），`numprcs` 回绕为小正值（如 4），导致 `prclyrnos` 仅分配 4 个槽位，而后续迭代器以真实的 `numhprcs=5` 计算 `prcno`，在 `prcvind ≥ 1` 时产生越界写操作。Release 编译下唯一的防护 `assert` 被消除，堆内存因此遭到破坏，攻击者可借此实现任意代码执行（RCE）或至少导致进程崩溃（DoS）。

#### Vulnerability Description (English)

At `jpc_dec.c:777`, `rlvl->numprcs` is computed as a plain `int` multiplication of `numhprcs × numvprcs` with no overflow guard. A crafted JPEG-2000 tile (e.g., width=5, height=858,993,460, `prcwidthexpn=prcheightexpn=0`) causes the product to wrap around to a small value (e.g., 4), so `prclyrnos` is under-allocated to 4 slots. The three progression-order iterator functions then compute `prcno` using the true `numhprcs=5`, writing past the allocated buffer at lines 310/411/505 once `prcvind ≥ 1`. The sole guard (`assert`) is stripped in Release builds, leaving the heap-corruption path fully exposed.

---

#### 触发方式 / Trigger

```bash
# Requires ≥16 GB free RAM for tile allocation to succeed
imginfo -f evil.jp2
```

调用链 / Call chain:

```
imginfo → jas_image_decode() → jpc_decode() → jpc_dec_tiledecode()
  → jpc_dec_tileinit()          [jpc_dec.c:777  — numprcs overflows]
  → jpc_t2dec_decode()
  → jpc_pi_nextrpcl/nextpcrl/nextcprl()
      [jpc_t2cod.c:308/408/503 — prclyrnos OOB write]
```

构造条件 / Craft requirements:

| Field | Value |
|---|---|
| COD `parwidthval` / `parheightval` | `0` (prcwidthexpn = prcheightexpn = 0) |
| Tile width × height | 5 × 858,993,460 (triggers int32 wrap) |
| Progression order | RPCL / PCRL / CPRL |

---

#### PoC 验证状态 / PoC Status

| 项目 | 详情 |
|---|---|
| 状态 Status | **VERIFIED_CRASH** |
| PoC 路径 Path | `/data/ylwang/non-textfuzz/target/_poc/jasper/src_libjasper_jpc_jpc_t2cod_c/001` |
| 崩溃类型 Crash type | Heap out-of-bounds write (`prclyrnos[prcno]` past allocation) |
