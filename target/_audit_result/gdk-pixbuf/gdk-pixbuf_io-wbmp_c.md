Now I have all the context needed. Let me perform the complete analysis.

**Analysis of io-wbmp.c:**

**Group 1: `get_mbi()` (lines 163–191)**
- `*val` is `int*` (signed 32-bit). Each loop iteration does `*val <<= 7` — signed left-shift is UB in C when result doesn't fit. With 4 continuation bytes all `0xFF` and terminator `0x7F`, the maximum decoded value is `0x0FFFFFFF = 268,435,455`. Values above that cause signed overflow / wrap, producing negatives caught by `<= 0` check. No escape from the validation.
- Short-circuit evaluation of `!rv || (intbuf[n-1] & 0x80)` at n=0 means `intbuf[-1]` is never actually accessed. No OOB read here.

**Group 2: `gdk_pixbuf_new()` allocation path (line 266)**
- Called with decoded width/height. The function checks `rowstride / channels != width` (truncation test) and `rowstride + 3 < 0` (alignment overflow test). With channels=3 and max width=268,435,455: rowstride=805,306,365; both checks pass. Alignment produces rowstride=805,306,368, stored as `int rowstride` in the `GdkPixbuf` struct. `g_try_malloc_n(height, rowstride)` uses `size_t` arithmetic so avoids overflow, returns NULL gracefully on OOM.

**Group 3: Pixel-writing loop (lines 281–318) — CRITICAL**

```c
ptr = context->pixbuf->pixels + context->pixbuf->rowstride * context->cury + context->curx * 3;
```

- `context->pixbuf->rowstride` is `int` (32-bit), `context->cury` is `int` (32-bit).
- Multiplication `rowstride * cury` is computed as **32-bit signed int × 32-bit signed int = 32-bit signed int** in C.
- With width=268,435,455 → rowstride=805,306,368, and height=4 (so cury reaches 3):
  - `805,306,368 × 3 = 2,415,919,104 > INT_MAX (2,147,483,647)` → **signed integer overflow**
  - Wraps to `2,415,919,104 − 4,294,967,296 = −1,879,048,192` (int32)
  - On x86-64: sign-extended to `0xFFFFFFFF90000000` (large negative 64-bit), added to 64-bit `pixels` pointer
  - `ptr` points 1.87 GB **before** the allocated buffer → heap underflow write
- The attacker controls `pixval` ∈ {0x00, 0xFF}; writes `ptr[0]=ptr[1]=ptr[2]=pixval` into arbitrary heap memory before the buffer, corrupting adjacent allocations/metadata.
- **Minimum-allocation trigger**: width=3, height=178,956,972 → 12 × 178,956,972 ≈ **2.15 GB** allocation (feasible on 64-bit systems with ≥4 GB RAM). Overflow occurs at cury=178,956,971: 12 × 178,956,971 = 2,147,483,652 > INT_MAX.
- `curx * 3`: max curx < 268,435,455, max curx×3 ≈ 805 M < INT_MAX — safe.

**Group 4: `getin()` / `save_rest()` bounds**
- `save_rest` checks `buf_size > (sizeof(last_buf) − last_len)` before memcpy. `last_len` is guaranteed ≤ 16 throughout (save_rest gating). No overflow path.

## VULN: Signed Integer Overflow in Pixel Row Pointer Arithmetic → Heap Out-of-Bounds Write
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf__wbmp_image_load_increment()
- **行号**: 296
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 7.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted WBMP image file
- **外部触发路径**: gdk_pixbuf_new_from_file() → _gdk_pixbuf_generic_image_load() → module->load_increment() → gdk_pixbuf__wbmp_image_load_increment() → pixel-writing loop at line 296
- **描述**: 在像素行写入循环中，指针偏移量通过 `context->pixbuf->rowstride * context->cury` 计算，两个操作数均为 `int`（32位有符号整数），乘积同样为32位有符号整数。当 width=268,435,455（4字节MBI最大值，rowstride=805,306,368）且 cury ≥ 3 时，乘积 805,306,368 × 3 = 2,415,919,104 超过 INT_MAX（2,147,483,647），产生有符号整数溢出，结果回绕为负值（−1,879,048,192）。在64位系统上，该负32位整数被符号扩展为负64位偏移，加到 `pixels`（64位指针）上，使 `ptr` 指向缓冲区分配起始地址之前约1.87 GB处。随后 `ptr[0]=ptr[1]=ptr[2]=pixval`（pixval∈{0x00,0xFF}）将像素数据写入堆上任意内存区域，破坏相邻堆块元数据或对象数据，构成堆缓冲区越界写（下溢）。
- **触发条件**: 构造 WBMP 文件，将 width 编码为 ≥ 238,609,295（MBI 4字节），height ≥ 4（使 cury 至少达到3）；或 width=3、height=178,956,972（rowstride=12，overflow 在 cury=178,956,971 时触发）。需要目标系统能成功分配约 2.15 GB 的连续堆内存（64位系统且可用内存充足时可行）。
- **安全影响**: 攻击者控制写入值（0x00 或 0xFF），向堆缓冲区前方的任意内存写入字节。在堆利用技术下，可能通过覆盖堆管理元数据（如 glibc malloc 的 chunk header）实现任意地址写原语，最终导致远程代码执行（RCE）；即使无法精确控制，也会导致进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
