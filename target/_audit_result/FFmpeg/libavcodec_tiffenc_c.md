I now have all the context needed. Let me summarize the analysis:

**Key finding — Line 410, DEFLATE path:**

- `bytes_per_row` is `int64_t`, bounded to ≤ `INT_MAX` by the explicit check at line 356.
- `s->rps` is `int`, set to `s->height` for DEFLATE (line 345).
- `zlen` is declared as `int` (line 407).
- The multiplication `bytes_per_row * s->rps` is computed as `int64_t * int = int64_t`, but **immediately truncated to `int`** when stored in `zlen`.
- If the true product exceeds `INT_MAX`, `zlen` wraps to a small positive value (or wraps negative, which fails on `av_malloc` but a wrap to small positive is exploitable).
- `zbuf = av_malloc(zlen)` allocates too little memory.
- The loop then copies `bytes_per_row` bytes per row for `s->rps` rows into `zbuf`, writing far past the allocated buffer → heap overflow.

**Concrete scenario:** `bytes_per_row = 8192` (width ≈ 2730 px RGB24), `height = 262145`:  
- True product: `8192 × 262145 = 2,147,491,840` → `INT_MAX = 2,147,483,648` → overflow by 8192  
- `zlen` wraps to **8192** (modulo 2³²)  
- `zbuf = av_malloc(8192)` succeeds  
- Loop writes `262145 × 8192 = ~2 GB` into an 8192-byte heap buffer → massive heap buffer overflow

The type_sizes discrepancy (type_sizes[2]=100 vs type_sizes2[2]=1 for AV_TIFF_STRING) is intentional — the sentinel value 100 forces strings to external storage always — not a vulnerability.

---

## VULN: Integer Overflow in DEFLATE zbuf Allocation Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: encode_frame()
- **行号**: 407-428
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (transcoded to TIFF with DEFLATE compression)
- **外部触发路径**: `ffmpeg -i crafted.mkv -vcodec tiff -compression_algo deflate output.tiff` → `avcodec_send_frame()` → `encode_frame()` → DEFLATE branch (lines 404–436) → `zlen = bytes_per_row * s->rps` (line 410) → `av_malloc(zlen)` (line 411) → `memcpy(zbuf + j * bytes_per_row, ...)` (line 424) → heap OOB write
- **描述**: 在 `encode_frame()` 的 DEFLATE 压缩路径中，第 407 行将 `zlen` 声明为 `int`，第 410 行计算 `zlen = bytes_per_row * s->rps`。`bytes_per_row` 为 `int64_t`（已被第 356 行上界限制为 ≤ `INT_MAX`），`s->rps` 为 `int`（DEFLATE 模式下等于 `s->height`）。C 语言规则使乘法在 `int64_t` 中完成，但结果立即被截断赋给 `int zlen`。当真实乘积超过 `INT_MAX` 时，`zlen` 回绕为一个小的正整数。随后 `zbuf = av_malloc(zlen)` 只分配了 `zlen` 字节的堆内存，但后续 for 循环（第 418–427 行）按真实行数（`s->rps` 行）× `bytes_per_row` 字节写入 `zbuf`，导致大量越界写入，破坏堆元数据及相邻对象。
- **触发条件**: 攻击者需构造一个源视频（如 MKV/MP4），使得解码后的帧宽高满足 `bytes_per_row × height > INT_MAX` 且 `bytes_per_row × height mod 2³²` 等于较小正整数。示例：`bytes_per_row = 8192`（对应约 2730 像素宽 RGB24 图像），`height = 262145`，乘积 `2,147,491,840` 回绕至 `8192`，导致仅分配 8192 字节缓冲区而实际写入约 2 GB 数据。需要目标系统选用 DEFLATE 压缩（`-compression_algo deflate`）并支持外包内存分配（外层 packet 分配约 4 GB，64 位 Linux overcommit 可能成功）。
- **安全影响**: 堆缓冲区大规模越界写入，可覆盖相邻堆对象、函数指针或堆管理元数据，最坏情况下可实现任意代码执行（RCE）；至少可导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
