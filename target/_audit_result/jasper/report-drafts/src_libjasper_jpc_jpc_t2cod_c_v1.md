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
