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
