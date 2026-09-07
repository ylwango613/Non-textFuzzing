I now have a complete picture of both files. Let me summarize my findings:

**Analysis of `io-gdip-utils.c` (the shared engine called by `io-gdip-tiff.c`):**

**Bug 1 — `gdip_bitmap_get_frame_delay`, lines 494–498:**
- `item = (PropertyItem *)g_try_malloc(item_size)` — no NULL-check before passing `item` to `GdipGetPropertyItem`
- `item_count = item_size / sizeof(long)` — **wrong formula**. `item_size` = `sizeof(PropertyItem)` + data bytes. The correct formula is `item->length / sizeof(long)`. Using the total buffer size inflates `item_count` by `sizeof(PropertyItem)/sizeof(long)` (= 4 on 32-bit, = 6 on 64-bit).
- Result: `((long *)item->value)[(frame < item_count) ? frame : item_count - 1]` can select an index past the actual data payload, reading beyond the end of the `g_try_malloc` allocation. E.g., with 1 delay entry (4 bytes data), `item_size = 20`, `item_count = 5`; for `frame = 1`, the read is at offset 20 of a 20-byte heap buffer — 4 bytes past the end.

**Bug 2 — three functions, lines 410, 494, 523:**
- `g_try_malloc` result is never checked for NULL before being passed to `GdipGetPropertyItem`. On OOM or `item_size == 0`, `GdipGetPropertyItem` writes to address NULL → crash.

---

## VULN: Heap Out-of-Bounds Read in gdip_bitmap_get_frame_delay via Wrong item_count Formula
- **漏洞类别**: memory-safety
- **函数**: `gdip_bitmap_get_frame_delay()` (io-gdip-utils.c, called by all GDI+ loaders including io-gdip-tiff.c via `gdip_fill_vtable`)
- **行号**: 494-498
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted animated image file (GIF/TIFF with PropertyTagFrameDelay tag)
- **外部触发路径**: 攻击者提供恶意图像文件 → `gdk_pixbuf__gdip_image_load_increment`（数据累积）→ `gdk_pixbuf__gdip_image_stop_load` → `gdip_buffer_to_bitmap` → `stop_load` (for each time-dimension frame, calls `gdip_bitmap_get_frame_delay(bitmap, i, &frame_delay)`) → `gdip_bitmap_get_frame_delay` 内部触发堆越界读
- **描述**: `gdip_bitmap_get_frame_delay` 从 GDI+ 读取 `PropertyTagFrameDelay` 属性时，先用 `GdipGetPropertyItemSize` 获得整个属性缓冲区的总字节大小 `item_size`（包含 `sizeof(PropertyItem)` 结构体开销 + 实际延迟数据），再用 `item = g_try_malloc(item_size)` 分配平坦缓冲区。随后计算 `item_count = item_size / sizeof(long)`，但 `item_size` 含有结构体头部（32-bit Windows 上 `sizeof(PropertyItem) = 16`），导致 `item_count` 比实际延迟条目数偏大 `sizeof(PropertyItem)/sizeof(long) = 4`。接下来 `((long *)item->value)[(frame < item_count) ? frame : item_count - 1]` 中的 "钳位" 保护失效——当 `frame` 在 `[item->length/sizeof(long), item_count)` 区间时，读取会超出平坦分配缓冲区末尾，造成堆越界读（heap OOB read）。例如：1 个延迟条目（4 字节数据）时 `item_size = 20`，`item_count = 5`，对第 2 帧（frame=1）：`((long*)item->value)[1]` 读取偏移 20 处——恰在 20 字节分配之外。
- **触发条件**: 攻击者构造一个含 `PropertyTagFrameDelay` 标签的图像文件，使该标签的延迟条目数少于图像的帧数。例如：一个有 2+ 帧（`FrameDimensionTime`）但只有 1 个 GCE 延迟块的 GIF；或一个显式写入 `PropertyTagFrameDelay` 标签但条目数不足的 TIFF 文件。当第 2 帧（frame=1）被处理时，`stop_load` 调用 `gdip_bitmap_get_frame_delay(bitmap, 1, ...)` 进入漏洞路径。
- **安全影响**: 堆越界读——读取紧邻分配块之后的堆内存，可造成：(1) 信息泄露（heap spray 情景下泄露内存布局或敏感数据，如 ASLR bypass）；(2) 进程崩溃（若越界地址不可访问）；与后续逻辑漏洞结合在某些平台上可能进一步利用。

## VULN: NULL Pointer Dereference via Unchecked g_try_malloc in Property Item Fetch Functions
- **漏洞类别**: memory-safety
- **函数**: `gdip_bitmap_get_property_as_string()` / `gdip_bitmap_get_frame_delay()` / `gdip_bitmap_get_n_loops()` (io-gdip-utils.c)
- **行号**: 410-411, 494-495, 523-524
- **CWE**: CWE-476 (NULL Pointer Dereference)
- **CVSS v3.1**: 4.3 (AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted image file triggering OOM or zero-size property
- **外部触发路径**: 攻击者提供图像文件 → `gdk_pixbuf__gdip_image_stop_load` → `stop_load` → `gdip_bitmap_get_frame_delay` / `gdip_bitmap_to_pixbuf` → `gdip_bitmap_get_property_as_string` → `g_try_malloc` 返回 NULL → `GdipGetPropertyItem(..., NULL)` 写入地址 0
- **描述**: 三个函数中均存在相同模式：`item = (PropertyItem *)g_try_malloc(item_size)` 的返回值未做 NULL 检查，直接作为输出缓冲区传给 `GdipGetPropertyItem`。在内存不足（OOM）或 `item_size == 0` 情况下，`g_try_malloc` 返回 NULL，而 `GdipGetPropertyItem` 将尝试向地址 NULL 写入属性数据，触发访问违规（空指针解引用），导致进程崩溃（拒绝服务）。
- **触发条件**: (1) 系统内存耗尽时打开恶意图像（攻击者先耗尽内存再投递图像）；(2) `GdipGetPropertyItemSize` 返回 0 字节大小（极端情况），`g_try_malloc(0)` 在部分平台返回 NULL。
- **安全影响**: 进程崩溃（拒绝服务）；在 Windows 上触发结构化异常，若异常处理器存在缺陷有进一步利用空间（低概率）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
