Based on my exhaustive multi-batch analysis of all 2442 lines of `jpc_dec.c` plus deep inspection of referenced headers (`jpc_dec.h`, `jpc_cs.h`, `jpc_cs.c`, `jpc_tagtree.c`, `jas_malloc.c`, `jas_seq.c`), I have identified the following memory safety vulnerabilities.

**Batch 1 (0-600):** SOT tileno validation present; no overflow in jas_alloc2 calls in process_sot.

**Batch 2 (600-1200):** `jpc_dec_tileinit()` – found UB chain when `prcwidthexpn=0` for non-LL resolution levels: `cbgwidthexpn = prcwidthexpn – 1 = –1` (line 798), which cascades into `1 << (–1)` (UB per C11 §6.5.7(3)), wrong `cblkwidthexpn` (UINT_FAST16_MAX via sign-conversion), and ultimately `numhcblks = numvcblks = 0`, triggering `jpc_tagtree_create(0,0)` which violates its internal `assert(numleafsh > 0 && numleafsv > 0)` precondition and executes a write (`node->parent_ = 0`) to a zero-byte heap allocation.

**Batch 3 (1200-1800):** `jpc_dec_process_siz()` – missing `return –1` at line 1283 after `jas_safe_size_add` overflow, allowing sample count to be incorrectly tracked; the final max_samples guard still fires in default builds but the bug weakens layered protection.

**Batch 4 (1800-2442):** `jpc_ppmstabtostreams()` – signed-shift UB: `(unsigned char) << 24` when byte ≥ 128 overflows signed int, sign-extends to `uint_fast32_t` on 64-bit, producing a wildly wrong `tpcnt`; leads to the error path rather than a heap write. `jpc_dec_cp_setfromqcx()` stepsizes loop correctly bounded (cap at 100 = `3*JPC_MAXRLVLS+1` confirmed in jpc_cs.c:1055). `jpc_streamlist_insert()` realloc arguments are internally consistent (no under-allocation).

## VULN: UB Negative-Shift → Zero-Size Heap Write in jpc_dec_tileinit via prcwidthexpn=0
- **漏洞类别**: memory-safety
- **函数**: jpc_dec_tileinit()
- **行号**: 798-885
- **CWE**: CWE-758 (Reliance on Undefined, Unspecified, or Implementation-Defined Behavior) / CWE-122 (Heap-Based Buffer Overflow)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted JP2/JPEG-2000 image file
- **外部触发路径**: imginfo → jpc_decode() → jpc_dec_decode() → jpc_dec_process_sod() → jpc_dec_tileinit() → (for rlvlno > 0 with prcwidthexpn=0) line 798: `rlvl->cbgwidthexpn = rlvl->prcwidthexpn – 1 = –1` → line 851: `1 << (–1)` (UB) → line 801-804: `rlvl->cblkwidthexpn = JAS_MIN(positive_uint_fast8_t, –1) = –1` stored as `uint_fast16_t` (becomes `0xFFFFFFFFFFFFFFFF` on 64-bit) → lines 863-874: shifts by `cblkwidthexpn & 63 = 63` produce `numhcblks = numvcblks = 0` → line 877: `jpc_tagtree_create(0, 0)` → jpc_tagtree.c:109 violates precondition `assert(numleafsh > 0 && numleafsv > 0)` → jpc_tagtree.c:159: `node->parent_ = 0` writes to zero-byte heap allocation
- **描述**: 当 COD/COC marker 带有 PRT 标志且 `parwidthval=0`（4 位字段，文件直接可控）时，非 LL 分辨率层（rlvlno > 0）的 `cbgwidthexpn = prcwidthexpn – 1 = 0 – 1 = –1`（int 类型，定义明确）。随后 `cbgxend = cbgxstart + (1 << –1)` 触发 C11 未定义行为（负数移位）；`rlvl->cblkwidthexpn = JAS_MIN(any_positive, –1) = –1` 被截断为 `uint_fast16_t`，在 64 位平台变为 `2^64-1`。之后的 FLOORDIVPOW2/CEILDIVPOW2 宏以 `(2^64-1) & 63 = 63` 为移位量，使得 `brcblkxend = tlcblkxstart = 0`，从而 `numhcblks = numvcblks = 0`，`numcblks = 0`。此后调用 `jpc_tagtree_create(0, 0)`：该函数在 0 字节堆分配上执行 `node->parent_ = 0`（8 字节写入），越界写入零长度分配边界之外。在调试构建中，两处 `assert` 触发 abort（行 109 in jpc_tagtree.c，行 875 in jpc_dec.c）；在发布构建中（NDEBUG），写操作落在 glibc 最小分配块内（无立即崩溃），但在严格分配器（ASAN/jemalloc）下将被捕获为堆缓冲区溢出。
- **触发条件**: 构造含 COD 或 COC marker 的 JPEG-2000 文件：将 Scod/Scoc 字节的 bit0（PRT 标志）置 1，并将至少一个 resolution level 的预制大小字节（parwidthval nibble）设为 0x0（即预制大小字节低 4 位为 0000），同时 numdlvls ≥ 1（至少存在一个非 LL 分辨率层）。
- **安全影响**: 在调试构建中可靠触发 abort（DoS）；在发布构建中通过 UB 导致零长度堆写越界；在 ASAN 或严格内存分配器下会被检测为堆缓冲区溢出，可导致进程崩溃（DoS）。在极端情况下（特定分配器布局），越界写入可能破坏相邻堆元数据，理论上可演化为代码执行，但在标准 glibc 下实际影响为 DoS。

## VULN: Missing Error Return After jas_safe_size_add Overflow in jpc_dec_process_siz
- **漏洞类别**: memory-safety
- **函数**: jpc_dec_process_siz()
- **行号**: 1282-1284
- **CWE**: CWE-252 (Unchecked Return Value) / CWE-190 (Integer Overflow)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L)
- **严重程度**: Low
- **攻击向量**: crafted JP2/JPEG-2000 image file
- **外部触发路径**: imginfo → jpc_decode() → jpc_dec_decode() → jpc_dec_process_siz() → 样本计数循环（lines 1265-1285）：`jas_safe_size_add` 返回 false 时仅打印错误但缺失 `return -1`，`num_samples` 保持旧值，继续进入后续逻辑
- **描述**: 在 `jpc_dec_process_siz()` 的样本计数循环中（lines 1265-1285），当 `jas_safe_size_add(num_samples, num_samples_delta, &num_samples)` 因 `size_t` 加法溢出而返回 false 时，代码仅输出错误信息，缺失应有的 `return -1`（对比第 1280-1281 行的 `jas_safe_size_mul` 失败路径正确地 `return -1`）。溢出后 `num_samples` 保留溢出前的旧值（`jas_safe_size_add` 在失败时不更新 `*result`），后续 max_samples 检查基于该错误值进行，削弱了图像尺寸的安全防护层次。在 `max_samples = 0`（禁用限制）的配置下，此缺陷可导致超大图像绕过累积样本数检测，允许超量内存分配。
- **触发条件**: 构造含多组件（numcomps 接近 16384）且每个组件样本数之和超过 `size_t` 最大值的 JP2 文件，并以 `max_samples=0` 选项调用解码器（如通过 `imginfo --max-samples 0 -f crafted.jp2`）。在默认 max_samples=64M 配置下由于单组件即超限而不可利用。
- **安全影响**: 默认配置下：轻微（逻辑错误，无实际内存破坏，因为最终 max_samples 检查仍能拦截超大单组件）；`max_samples=0` 配置下：可能导致极大内存分配操作（DoS），在极端情况下可能绕过样本数限制导致后续分配不足。

<!-- AUDIT_PROMPT_VERSION: 1 -->
