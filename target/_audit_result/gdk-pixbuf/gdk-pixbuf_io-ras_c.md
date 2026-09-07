I have confirmed the critical vulnerability. The key facts:

1. `pixbuf->rowstride` is `int` (32-bit, from gdk-pixbuf.c line 441).  
2. `context->Lines` is `gint` (32-bit).  
3. Line 303: `rowstride * Lines` is a 32-bit signed multiplication — wraps on overflow.  
4. `gdk_pixbuf_new` allows a width of up to 536870911 for 4-channel images (rowstride = 2147483644 passes `rowstride/4 == width` and `rowstride+3 >= 0`).  
5. For height = 3: Lines reaches 2, and `2147483644 * 2 = 4294967288` wraps to `-8` as int32.  
6. On 64-bit, the negative int is sign-extended: `pixels + (-8) = pixels - 8` → OOB write before the allocation.

## VULN: Integer Overflow in `rowstride * Lines` Causes Heap OOB Write in OneLine* Functions
- **漏洞类别**: memory-safety
- **函数**: OneLine32() / OneLine24() / OneLine8() / OneLine1()
- **行号**: 303, 320, 338, 357
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-bounds Write)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted RAS image file (Sun Raster format)
- **外部触发路径**: malicious .ras file → `gdk_pixbuf__ras_image_load_increment()` → `OneLine()` → `OneLine32()`/`OneLine24()`/`OneLine8()`/`OneLine1()`
- **描述**: 在所有 `OneLine*` 函数中，第 303/320/338/357 行执行 `context->pixbuf->rowstride * context->Lines`，其中 `rowstride` 和 `Lines` 均为 `int`/`gint`（有符号32位整数）。当两者乘积超过 INT_MAX 时发生有符号整数溢出，结果变为负值。在64位平台上，该负值被符号扩展为64位偏移，导致 `Pixels` 指针指向 `pixbuf->pixels` 缓冲区之前的堆内存，后续逐像素写入（`Pixels[X*N + k] = ...`）发生堆越界写入。根本原因是 `RAS2State()` 对 width/height 只检查 `(gint)val <= 0`，未对 `rowstride * height` 的乘积溢出进行任何验证，而 `gdk_pixbuf_new()` 的溢出检查仅覆盖 `width * channels`（rowstride 本身），不覆盖 `rowstride * height` 作为偏移时的再次溢出。
- **触发条件**: 构造 RAS 文件设置 `depth=32`（RasType=32，4通道），`width=536870911`（使得 `rowstride=2147483644`，恰好通过 `gdk_pixbuf_new` 的 `rowstride/4==width` 和 `rowstride+3≥0` 双重检查），`height=3`（最少3行即可触发），`type=2`（RT_BYTE_ENCODED 压缩，可大幅压缩输入数据量）。在启用内存过量提交（`vm.overcommit_memory=1`）的64位 Linux 系统上，`g_try_malloc_n(3, 2147483644)` = 6.4 GB 会成功返回，加载前两行正常写入，到第三行（Lines=2）时 `2147483644 × 2 = 4294967288` 溢出为 int32 的 `-8`，Pixels 指针指向像素缓冲区起始地址前8字节，导致覆盖该地址前的堆元数据或相邻对象。
- **安全影响**: 攻击者可精心控制写入位置（堆元数据/相邻 chunk header），结合 GNOME 图像查看器或 GTK+ 应用自动加载缩略图的场景，存在远程代码执行（RCE）或可靠拒绝服务（进程崩溃）风险。

<!-- AUDIT_PROMPT_VERSION: 1 -->
