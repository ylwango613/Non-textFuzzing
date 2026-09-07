Analysis complete. The key finding: `gdk_pixbuf_new` only checks `width * channels` for int overflow (line 450), but **not** `height * rowstride`. On a 64-bit system, `g_try_malloc_n(height, rowstride)` uses size_t arithmetic and can succeed for allocations > INT_MAX bytes. However, the OFFSET macro at line 399 uses signed 32-bit int arithmetic — so `y * rowstride` overflows when `(height-1) * rowstride > INT_MAX`, producing a negative offset and causing out-of-bounds reads/writes.

## VULN: OFFSET Macro Signed Integer Overflow → Heap OOB Read/Write in gdk_pixbuf_rotate_simple and gdk_pixbuf_flip
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf_rotate_simple(), gdk_pixbuf_flip()
- **行号**: 399, 447-491, 543-559
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 / CWE-125 (Out-of-bounds Write / Read)
- **CVSS v3.1**: 7.8 (AV:L/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted image file (PNG/JPEG with extreme width or height dimension)
- **外部触发路径**: gdk_pixbuf_new_from_file() / gdk_pixbuf_loader → gdk_pixbuf_rotate_simple() or gdk_pixbuf_flip() → `OFFSET(pb, x, y)` macro → signed int overflow in `y * pb->rowstride`
- **描述**: `gdk_pixbuf_new` (gdk-pixbuf.c:450) only guards against `width * channels` overflowing `int`, but passes `height` and `rowstride` to `g_try_malloc_n` as `gsize` (size_t), allowing allocations where `height * rowstride > INT_MAX` to succeed on 64-bit systems. The OFFSET macro at line 399 is defined as `((x) * (pb)->n_channels + (y) * (pb)->rowstride)` — all operands are `int`, so when `y * rowstride > INT_MAX`, C signed-integer overflow (undefined behaviour, wraps to negative on x86-64) produces a negative computed offset. Both pixel read pointer (`p = src_pixels + OFFSET(src, x, y)`, line 447/468/489) and write pointer (`q = dest_pixels + OFFSET(dest, ...)`, lines 448/469/490) become sub-buffer, causing heap OOB read and write. In `gdk_pixbuf_flip` the same macro drives the write at lines 545/556.
- **触发条件**: 攻击者构造一张 width × height 的 RGBA 图像，使得 `(height - 1) * rowstride > INT_MAX`（例如 width = 536870911、height = 3、RGBA，总分配 ≈ 6.4 GB），在拥有足够内存的 64 位系统上被 `gdk_pixbuf_rotate_simple` 或 `gdk_pixbuf_flip` 处理时触发溢出。对于高度大、宽度小的图像（例如 width = 1、height = 600000000、RGBA，分配 ≈ 2.4 GB），同样触发：y = 536870912 时 `y * 4` 溢出。
- **安全影响**: 在 64 位高内存服务器（图像处理服务、GNOME 桌面应用）上，堆缓冲区越界写入可损坏紧邻的堆 chunk 头部或其他堆对象，经精心构造可导致远程/本地代码执行（RCE）；最坏情况即使不可精确控制也可引发可重复崩溃（DoS）。越界读同时导致堆内容泄漏（信息泄露）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
