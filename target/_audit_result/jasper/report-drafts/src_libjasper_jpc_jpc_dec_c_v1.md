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
