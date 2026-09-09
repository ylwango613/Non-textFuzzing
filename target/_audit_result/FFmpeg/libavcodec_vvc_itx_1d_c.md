I have fully traced the vulnerability. Let me compile the final audit report.

**Summary of analysis:**

**Group 1 (lines 1–641): DCT2/dct2_2/4/8/16/32/64 functions** — These use the `G2/G4/G8/G16` macros that test `nz` themselves and all reads are from fixed `coeffs[n * stride]` where n ≤ 63. No OOB — clean.

**Group 2 (lines 644–693): `matrix_mul` / `ff_vvc_inv_dct8_{4,8,16,32}` / `ff_vvc_inv_dst7_{4,8,16,32}`**

Critical finding: `matrix_mul` at line 647 declares `int tmp[16]` (a 16-element fixed stack buffer). The loop at lines 649–650 writes `nz` elements without any bounds check:
```c
for (int i = 0; i < nz; i++)
    tmp[i] = coeffs[i * stride];   // OOB write when nz > 16
```

`nz` arrives from the caller chain: `ff_vvc_inv_dct8_32(..., nz)` → `inv_dct8(..., 32, nz)` → `matrix_mul(..., 32, nz)`.

In `intra.c:itx_2d()`, `nzw = tb->max_scan_x + 1` and `nzh = tb->max_scan_y + 1` are passed as `nz`. These are updated in `cabac.c:2396` directly from parsed bitstream positions with no filtering by transform type. For a 32-point DCT8/DST7 block, positions 0–31 are legal in the coefficient coding, so an attacker can push `max_scan_x` to 31, giving `nzw = 32` → 16 integers (64 bytes) written past `tmp[16]`.

The comment at line 646 acknowledges the assumption ("for dst7 and dct8, coeffs > 16 are zero out") but does NOT enforce it—making this an assumption that a conformant encoder satisfies but a malformed bitstream can violate.

`ff_vvc_inv_dct8_32`/`ff_vvc_inv_dst7_32` are reachable via:
- SBT mode + 32-wide TU block (lines 158–160 of `intra.c`, no width constraint)
- Explicit MTS inter/intra with `mts_idx ∈ {2,4}` (line 167–168, block max ≤ 32)

**Group 3 (lines 695–708): `ff_vvc_inv_lfnst_1d`** — `lfnst_idx-1` is always ≥ 0 because `apply_lfnst_flag` is set only when `lfnst_idx ≥ 1`. Array bounds of `ff_vvc_lfnst_{4x4,8x8}[4][2][16][...]` are respected. Clean.

---

## VULN: Stack Buffer Overflow in matrix_mul via DCT8/DST7 32-point Transform
- **漏洞类别**: memory-safety
- **函数**: matrix_mul()
- **行号**: 644-661
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted VVC media file
- **外部触发路径**: ffmpeg -i crafted.vvc -f null - -> avformat_open_input() -> avcodec_open2() -> ff_vvc_decode_frame() [dec.c] -> vvc_decode_slice() -> ff_vvc_decode_ctu() [ctu.c] -> ff_vvc_reconstruct() -> transform_unit() [intra.c] -> itx_2d() [intra.c:452-457] -> fc->vvcdsp.itx.itx[VVC_DCT8][VVC_TX_SIZE_32](tb->coeffs, stride, nzw) = ff_vvc_inv_dct8_32() [itx_1d.c:669-672] -> inv_dct8() [itx_1d.c:663-666] -> matrix_mul() [itx_1d.c:644] → stack buffer overflow at line 650
- **描述**: `matrix_mul()` 在栈上声明了固定大小的 `int tmp[16]`（16 个元素），然后在没有任何边界检查的情况下循环 `nz` 次向其写入：`for (int i = 0; i < nz; i++) tmp[i] = coeffs[i * stride]`。当 VVC 码流使用 32 点 DCT8 或 DST7 变换时，`nz` 参数来自 `tb->max_scan_x + 1`，而 `max_scan_x` 在 `cabac.c:2396` 处直接从码流解析的系数坐标更新，对变换类型无过滤。VVC 规范要求 32 点 DCT8/DST7 的第 16–31 号系数为零（zero-out 区域），但 FFmpeg 实现仅以注释说明此假设（第 646 行），并未用代码强制执行。当畸形码流在第 16–31 号位置标记非零系数时，`max_scan_x` 可高达 31，使 `nzw = 32`，导致向 `tmp[16..31]` 写入 16 个 `int`（64 字节），栈上局部变量和返回地址被覆盖。
- **触发条件**: 构造一个 VVC 文件：①启用 SBT 模式（`cu->sbt_flag=1`）或显式 MTS（`mts_idx` 为 2 或 4）以将 32 点水平变换设为 DCT8/DST7；②在 32-宽变换块中于扫描位置 x ≥ 16 处插入非零系数（通过设置 `last_sig_coeff_x` ≥ 16 使 CABAC 在该位置编码非零系数），使解码器的 `tb->max_scan_x` 超过 15，进而 `nzw > 16`。
- **安全影响**: 栈上 64 字节连续越界写入，可覆盖相邻局部变量和返回地址。攻击者通过控制系数值可精确控制写入内容，在 ASLR/Stack Canary 保护缺失或被绕过的情况下可达到任意代码执行（RCE）；在有保护机制的环境中至少可稳定触发崩溃（DoS）。该函数在常规视频解码热路径中被反复调用，可靠性高。

<!-- AUDIT_PROMPT_VERSION: 1 -->
