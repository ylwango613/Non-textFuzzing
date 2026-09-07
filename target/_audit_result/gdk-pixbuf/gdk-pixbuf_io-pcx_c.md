I now have a complete picture. Here is my analysis summary before writing the final output:

- `context->line` is allocated at line 645 as `bytesperline × num_planes` bytes.
- All `pcx_increment_load_data_*` functions iterate `for(i = 0; i < context->width; i++)` and access `planes[0][i]` (or `planes[p][i/8]` for 1-bit) **without any validation that `width ≤ bytesperline`**.
- For 8-bit (num_planes=1): `context->line` has only `bytesperline` bytes; `planes[0][i]` for `i ≥ bytesperline` reads past the heap allocation.
- For 24-bit (num_planes=3): `context->line` has `3×bytesperline` bytes; `planes[2] = line + 2×bytesperline`, so `planes[2][i]` for `i ≥ bytesperline` reads `line[2×bytesperline + i]` which is past `line[3×bytesperline - 1]`.
- For 1-bit: `read_pixel_1(planes[0], i)` accesses `planes[0][i/8]`; if `width > 8×bytesperline`, up to 8190 bytes past end (width=65536, bytesperline=1).
- Line 652: `sizeof(guchar) * context->width * context->height` — on 32-bit systems, 65536×65536 overflows `size_t` to 0 → `g_try_malloc(0)` succeeds → OOB writes.

## VULN: Heap OOB Read in 8-bit PCX Decoder (width > bytesperline)
- **漏洞类别**: memory-safety
- **函数**: pcx_increment_load_data_8()
- **行号**: 445-449
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted PCX image file
- **外部触发路径**: gdk_pixbuf__pcx_load_increment() → PCX_TASK_LOAD_DATA → pcx_increment_load_data_8() → planes[0][i] OOB read
- **描述**: `context->line` is allocated at line 645 as `bytesperline × num_planes` bytes; for 8-bit images `num_planes == 1`, so the buffer is exactly `bytesperline` bytes. `planes[0]` is set to `context->line`. The pixel extraction loop at lines 448-449 iterates `i = 0..width-1` and reads `planes[0][i]` unconditionally. There is no check that `context->width ≤ context->bytesperline`. When `width > bytesperline`, every access with index `i ≥ bytesperline` reads bytes past the end of the heap-allocated `context->line` buffer. The out-of-bounds bytes are then written into `context->p_data` (which is later decoded to final pixel RGB via the palette), making the heap leak observable in the output image.
- **触发条件**: 构造一个 PCX 文件，其 header 中的 `xmax - xmin + 1`（width）大于 `bytesperline`（例如 width=1000, bytesperline=2）。8-bit 深度（`bitsperpixel=8, colorplanes=1`）。其余 header 字段合法。
- **安全影响**: 泄露 `context->line` 后相邻堆内存内容（含堆元数据、指针）进入输出图像像素数据，可用于信息泄露；结合堆风水可辅助 bypass ASLR，进一步利用可能导致 RCE。

## VULN: Heap OOB Read in 24-bit PCX Decoder (planes[2] Past End of line Buffer)
- **漏洞类别**: memory-safety
- **函数**: pcx_increment_load_data_24()
- **行号**: 517-527
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted PCX image file
- **外部触发路径**: gdk_pixbuf__pcx_load_increment() → PCX_TASK_LOAD_DATA → pcx_increment_load_data_24() → planes[2][i] OOB read
- **描述**: For 24-bit images (`bpp=24`, mapped from `bitsperpixel=8, colorplanes=3`), `context->line` is allocated as `bytesperline × 3` bytes (line 645). The three plane pointers are set up as: `planes[0] = context->line`, `planes[1] = planes[0] + bytesperline`, `planes[2] = planes[1] + bytesperline` (lines 517-519). The valid index range for `planes[2]` is `[0, bytesperline-1]` (i.e., `context->line[2×bytesperline .. 3×bytesperline-1]`). The pixel loop at lines 524-527 reads `planes[2][i]` for `i = 0..width-1`. When `width > bytesperline`, `planes[2][i]` for `i ≥ bytesperline` accesses `context->line[2×bytesperline + i]` which is at or past index `3×bytesperline`, beyond the allocation boundary. The OOB bytes are directly written into `context->data` (the pixbuf pixel buffer) as blue-channel values.
- **触发条件**: 构造 PCX 文件：`bitsperpixel=8, colorplanes=3`（version=5），`width > bytesperline`（例如 width=2000, bytesperline=1）。
- **安全影响**: 邻近堆内存字节被写入输出图像蓝色通道，可实现堆内容泄露；同上，可辅助利用链。

## VULN: Heap OOB Read in 1-bit PCX Decoder via read_pixel_1 (width >> 8×bytesperline)
- **漏洞类别**: memory-safety
- **函数**: pcx_increment_load_data_1() / read_pixel_1()
- **行号**: 317-322 (调用点), 244-260 (read_pixel_1 实现)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted PCX image file
- **外部触发路径**: gdk_pixbuf__pcx_load_increment() → PCX_TASK_LOAD_DATA → pcx_increment_load_data_1() → read_pixel_1(planes[p], i) → data[i/8] OOB read
- **描述**: For 1-bit PCX images (`bpp=1`), each `planes[p]` points into `context->line` which has `bytesperline × num_planes` bytes (line 645). `read_pixel_1(planes[p], i)` computes byte offset as `i / 8` and reads `data[i/8]`. The outer pixel loop iterates `i = 0..width-1`, so the maximum byte index accessed is `(width-1)/8`. There is no check that `(width-1)/8 < bytesperline`. An attacker can set `width=65536` (from `xmax=32767, xmin=-32768`) and `bytesperline=1` (num_planes=1), causing the allocation of 1 byte at `context->line` and subsequent reads up to `planes[0][8191]`—8190 bytes past the heap allocation boundary. The amplification factor (up to ×8191) makes this particularly severe.
- **触发条件**: 构造 PCX 文件：`bitsperpixel=1, colorplanes=1`，`xmin=-32768, xmax=32767`（width=65536），`bytesperline=1`。
- **安全影响**: 读取超出 `context->line` 8190 字节的堆内存，极大概率触发 crash（SIGSEGV/读保护区）实现 DoS，或在堆连续布局下大范围泄露堆内存指针，破坏 ASLR 进而辅助 RCE。

## VULN: Integer Overflow in p_data Allocation on 32-bit Systems (width×height Wraps to 0)
- **漏洞类别**: memory-safety
- **函数**: gdk_pixbuf__pcx_load_increment()
- **行号**: 652
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 5.5 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:L/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted PCX image file (32-bit target)
- **外部触发路径**: gdk_pixbuf__pcx_load_increment() → line 652: `g_try_malloc(sizeof(guchar) * context->width * context->height)` → integer overflow → OOB write in pcx_increment_load_data_8()
- **描述**: At line 652, `context->p_data` is allocated as `sizeof(guchar) * context->width * context->height`. On 32-bit systems where `size_t` is 32-bit, if both `context->width` and `context->height` equal 65536 (achievable via `xmax=32767, xmin=-32768`), the multiplication `(size_t)65536 * (size_t)65536 = 4,294,967,296` wraps to 0. `g_try_malloc(0)` in GLib returns a non-NULL minimal allocation (the NULL check at line 653 passes). Subsequently, `pcx_increment_load_data_8()` writes `height × width = 65536×65536 ≈ 4 GB` of pixel index bytes into the 0-byte allocation, causing a massive heap buffer overflow and memory corruption.
- **触发条件**: 32-bit 目标进程；PCX 文件设置 `xmin=-32768, xmax=32767, ymin=-32768, ymax=32767`（width=height=65536），`bitsperpixel=8, colorplanes=1`。
- **安全影响**: 在 32-bit 进程中发生大范围堆写越界，破坏堆结构，极大概率导致 RCE；现代 64-bit 平台上 `size_t` 为 64-bit 不触发此溢出，影响范围限于遗留 32-bit 部署。

<!-- AUDIT_PROMPT_VERSION: 1 -->
