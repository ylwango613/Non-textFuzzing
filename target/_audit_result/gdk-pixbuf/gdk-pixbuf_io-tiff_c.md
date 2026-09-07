Now I have all the types confirmed. Key facts:
- `tsize_t = tmsize_t = TIFF_SSIZE_T` (signed 64-bit `ssize_t` on x86_64)
- `toff_t = uint64_t` (unsigned 64-bit)
- `TiffContext::used`, `TiffContext::allocated`, `TiffContext::pos` are all `guint` (unsigned 32-bit)

**Analysis of `make_available_at_least` (lines 452–472):**

```c
need_alloc = context->used + needed;   // guint + guint = guint → wraps at 2^32
if (need_alloc > context->allocated) {
    guint new_size = 1;
    while (new_size < need_alloc)      // guint doubling → overflows to 0 → infinite loop
        new_size *= 2;
    new_buffer = g_try_realloc (context->buffer, new_size);
    ...
    return TRUE;  // or FALSE
}
return TRUE;   // ← returned without growing buffer when need_alloc wraps to ≤ allocated
```

**Scenario A — Infinite Loop (need 2 GB file):** When `context->used = 0x80000000` (2 GB) and `needed = 1`, `need_alloc = 0x80000001`. In the `while` loop, `new_size` doubles to `0x80000000`; `0x80000000 < 0x80000001` is TRUE (both `guint`), so `new_size *= 2` → overflows to **0**; then `0 < 0x80000001` → TRUE again → stuck at `0 * 2 = 0` forever.

**Scenario B — Heap Buffer Overflow (need ~4 GB file):** When `context->used ≈ 0xFFFFFFF0` and `needed = 0x20`, `need_alloc = 0x10` (wrapped). `0x10 > context->allocated (~4 GB)` is FALSE, so `make_available_at_least` returns TRUE without reallocating. Then back in `gdk_pixbuf__tiff_image_load_increment` (line 493): `memcpy(context->buffer + 0xFFFFFFF0, buf, 0x20)` writes 32 bytes starting 16 past the end of the buffer → heap buffer overflow.

## VULN: Integer Overflow in make_available_at_least Leading to Infinite-Loop DoS
- **漏洞类别**: memory-safety
- **函数**: make_available_at_least()
- **行号**: 457-461
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-835 (Loop with Unreachable Exit Condition)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF image file (≥ 2 GB raw size)
- **外部触发路径**: crafted TIFF file → gdk_pixbuf_new_from_file() / loader → gdk_pixbuf__tiff_image_begin_load() → gdk_pixbuf__tiff_image_load_increment() [called repeatedly with chunks] → make_available_at_least() → infinite loop
- **描述**: `make_available_at_least` 在第 457 行计算 `need_alloc = context->used + needed`，两者均为 `guint`（32 位无符号整型）。当 `context->used` 达到约 2 GB（`0x80000000`）且 `needed = 1` 时，`need_alloc = 0x80000001`，进入第 460–461 行的 while 循环：`guint new_size = 1; while (new_size < need_alloc) new_size *= 2`。循环中 `new_size` 从 1 翻倍至 `0x80000000`，此时 `0x80000000 < 0x80000001`（无符号比较）为 TRUE，再翻倍：`0x80000000 * 2 = 0x100000000` 溢出截断为 **0**（guint），随后 `0 < 0x80000001` 永真，`0 * 2 = 0` 无限循环，进程完全挂死。
- **触发条件**: 攻击者提供一个原始（压缩前）体积 ≥ 2 GB 的合法 TIFF 文件（如大型卫星图像、多层医疗影像）。TIFF 格式支持任意大图像，2 GB 文件在科学/地理领域并不罕见。对于支持 progressive loading 的应用（如 GNOME Files/eog），无需用户任何额外操作，仅打开目录即可触发。
- **安全影响**: 应用进程永久挂死（CPU 占用 100%），需外部强制终止；若进程为服务进程（如图片转码服务），造成持续 DoS。

## VULN: Integer Overflow in make_available_at_least Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: make_available_at_least() / gdk_pixbuf__tiff_image_load_increment()
- **行号**: 457, 484-493
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF image file (≥ ~4 GB raw stream)
- **外部触发路径**: crafted TIFF file → gdk_pixbuf__tiff_image_begin_load() → gdk_pixbuf__tiff_image_load_increment() [repeated chunks] → make_available_at_least(context, size) → 返回 TRUE（未增长缓冲区）→ memcpy(context->buffer + context->used, buf, size) 越界写
- **描述**: 在第 457 行，`need_alloc = context->used + needed` 以 `guint`（32 位无符号整型）计算。当 `context->used ≈ 0xFFFFFFF0`（约 4 GB - 16）且 `needed = 0x20`（32 字节）时，`need_alloc = 0x10`（向下溢出）。条件 `need_alloc (0x10) > context->allocated (0xFFFFFFF0)` 为 FALSE，函数直接 `return TRUE` 而未执行 realloc。随后第 493 行 `memcpy(context->buffer + 0xFFFFFFF0, buf, 0x20)` 向缓冲区末尾以外 16 字节起写入 32 字节，造成堆越界写入，可覆盖相邻堆元数据或对象。
- **触发条件**: 攻击者提供总字节数恰好使 `context->used` 接近 `UINT32_MAX` 的 TIFF 文件流（约 4 GB），随后再传入少量增量块使加法溢出。在 64 位系统中系统内存充足时可实现（如服务端图片处理管线）。
- **安全影响**: 堆元数据破坏，最坏情况下通过堆布局控制实现任意代码执行（RCE）；最低限度造成进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
