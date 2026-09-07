I now have a complete picture of the code. Let me synthesize the analysis:

**Key findings from full read (lines 1–1123):**

**Group 1 (lines 1–163): `setup_png_transformations`** — proper bit-depth, channel, width/height=0 checks. Transformations verified. No issues.

**Group 2 (lines 246–354): `gdk_pixbuf__png_image_load` (non-progressive)**
- Line 306: `gdk_pixbuf_new(…, w, h)` passes `png_uint_32` as `int`. `gdk_pixbuf_new` has `width > 0` guard + `rowstride/channels != width || rowstride+3 < 0` overflow check → allocation is sound.
- Lines 321-325:
  ```c
  rows = g_new (png_bytep, h);
  for (i = 0; i < h; i++)
      rows[i] = pixbuf->pixels + i * pixbuf->rowstride;
  ```
  `i` = `gint` (int32_t), `pixbuf->rowstride` = `int` (int32_t). Product `i * rowstride` is **signed 32-bit multiply** — undefined behavior (in practice wraps to negative) when `i * rowstride > INT_MAX`.
  
  Concrete trigger: width=537 (RGBA), height=1,000,000 (libpng default `PNG_USER_HEIGHT_MAX`):
  - rowstride = 537×4 = 2148
  - Buffer = 1,000,000 × 2148 = 2.148 GB (feasible on 64-bit systems with 4+ GB RAM)
  - First overflow at `i ≈ 999,760`: `999,760 × 2148 = 2,147,484,480 > INT_MAX=2,147,483,647`
  - `rows[999760..999999]` compute negative int offset, sign-extended on 64-bit → pointer ~2 GB **before** `pixbuf->pixels`
  - `png_read_image` writes attacker-controlled row data to those addresses → **heap underflow / OOB write**

**Group 3 (lines 593–694): `png_info_callback`** — `gdk_pixbuf_new` called with original width/height, size_func results unused for allocation. Not exploitable.

**Group 4 (lines 698–735): `png_row_callback` (progressive mode)**
- Line 732: `old_row = lc->pixbuf->pixels + (row_num * lc->pixbuf->rowstride)`
- `row_num` = `png_uint_32` (uint32_t) × `int` → unsigned 32-bit result (unsigned wins in C integer promotion when both are 32-bit).
- With height=1M and rowstride=2148: `999,999 × 2148 = 2,147,997,852 < UINT32_MAX` → no overflow for this dimension.
- Overflow only for `rowstride > 4295` (width ≥ 1074 RGBA), needing 4.3+ GB allocation. Writes wrap within buffer → data corruption but not OOB. Less severe than VULN 1.

**Group 5 (lines 815–1059): `real_save_png`** — uses trusted pixbuf fields, key/value validation in place. No memory safety issues.

---

## VULN: Signed Integer Overflow in Row-Pointer Initialization Leads to Heap Out-of-Bounds Write (PNG Loader)
- **漏洞类别**: memory-safety
- **函数**: `gdk_pixbuf__png_image_load()`
- **行号**: 321-326
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file (PNG)
- **外部触发路径**: crafted PNG file → `gdk_pixbuf__png_image_load()` → row-pointer loop (lines 323-325) → `png_read_image()` writes attacker-controlled pixel data to out-of-bounds addresses
- **描述**: 在非渐进式 PNG 加载函数 `gdk_pixbuf__png_image_load` 中，构造行指针数组时（第 323-325 行）：`rows[i] = pixbuf->pixels + i * pixbuf->rowstride;`，循环变量 `i` 为 `gint`（`int32_t` 有符号），`pixbuf->rowstride` 亦为 `int`，两者相乘结果类型为有符号 `int32_t`。当乘积超过 `INT_MAX = 2,147,483,647` 时发生有符号整数溢出（C 标准 UB，x86-64 实践上回绕为负值）。溢出后的负 `int` 在 64 位指针算术中被符号扩展为 `0xFFFFFFFF8xxxxxxx`，使 `rows[i]` 指向 `pixbuf->pixels` 起始地址之前约 2 GB 处。随后 `png_read_image()` 遍历 `rows[]`，将攻击者全控的像素行数据写入这些越界指针所指向的内存，造成堆缓冲区越界写（下溢方向）。
- **触发条件**: 攻击者构造一张宽度 ≥ 537 像素（RGBA，rowstride ≥ 2148）、高度 = 1,000,000 行（libpng 默认 `PNG_USER_HEIGHT_MAX`）的合法 PNG 文件。缓冲区总大小约 2.148 GB，在具有 4 GB 以上可用内存的现代 64 位系统上 `g_try_malloc_n` 可成功分配。首次溢出发生在 `i ≈ 999,760`，之后每一行（共约 240 行）的 `rows[i]` 均指向 `pixbuf->pixels` 之前约 2 GB 的内存区域，libpng 对这些地址执行攻击者可控的写操作。
- **安全影响**: 利用者可向目标进程地址空间中位于 PNG 像素缓冲区之前约 2 GB 处的堆内存（或其他映射区域）写入任意攻击者控制的数据，最坏情况下可实现远程代码执行（RCE）；若目标地址未映射，则导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
