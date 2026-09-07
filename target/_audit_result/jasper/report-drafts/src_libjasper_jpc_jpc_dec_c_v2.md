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
