Overflow chain confirmed: `pixmap_resize` return value is not checked (line 792), and `render()` blindly writes `w * h * 4` GLshort values into the buffer allocated with size 0 (or a tiny allocation). Both `jas_image_render` and `jas_image_render2` write without additional bounds checking.

## VULN: Integer Overflow in pixmap_resize() Leads to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: pixmap_resize()
- **行号**: 851-861 (overflow at 854); writes at 952-968 and 907-931
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted JPEG-2000 image file with large dimensions (e.g., width=height=32768)
- **外部触发路径**: `main()` → `nextimage()` → `loadimage()` → `jas_image_decode()` [decodes crafted JP2, sets image width/height from SIZ marker] → `vw = jas_image_width(gs.image)` [line 769, vw=32768] → `pixmap_resize(&gs.vp, vw, vh)` [line 792] → `realloc(p->data, w * h * 4 * sizeof(GLshort))` [line 854, size overflows to 0] → `render()` [line 796] → `jas_image_render2()` / `jas_image_render()` [write w*h*4 GLshorts into undersized buffer]
- **描述**: 在 `pixmap_resize(pixmap_t *p, int w, int h)` 的第854行，`realloc(p->data, w * h * 4 * sizeof(GLshort))` 中乘法 `w * h * 4` 全部在有符号 `int` 精度下计算。当 `w = h = 32768` 时，`32768 * 32768 = 2^30`（未溢出），再 `* 4 = 2^32` 作为 int32 回绕为 0；最终传给 realloc 的 size 为 0。glibc 的 `realloc(ptr, 0)` 在 ptr 非 NULL 时返回合法非空指针（最小堆分配），第854行的 NULL 检查因此通过，`p->data` 被赋值为该零字节缓冲区。随后 `loadimage()` 无条件调用 `render()`（line 796），后者调用 `jas_image_render2()` 或 `jas_image_render()`，以嵌套循环向 `gs.vp.data` 写入 `vh × vw × 4 = 32768 × 32768 × 4 ≈ 4.3 亿`个 GLshort 值（约 8 GB），远超分配大小，造成大规模堆越界写。
- **触发条件**: 攻击者构造一个 JPEG-2000 文件，其 SIZ marker 中 `Xsiz=32768, Ysiz=32768`（宽高均为 32768 像素）。JPEG-2000 标准支持此尺寸，解码器在设置图像元数据时无需实际分配全部像素数据，即可使 `jas_image_decode()` 成功返回。
- **安全影响**: 堆缓冲区大量越界写入（8 GB）可覆盖相邻堆对象、堆管理元数据，攻击者可精心控制覆盖内容实现任意代码执行（RCE）；最低影响为进程崩溃（DoS）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
