I've thoroughly reviewed the full file. Let me now deliver the final audit report.

## VULN: Signed Integer Overflow in Row Pointer Arithmetic Leads to Heap OOB Write
- **漏洞类别**: memory-safety
- **函数**: pixbuf_create_from_xpm()
- **行号**: 589-616
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-787 (Out-of-Bounds Write)
- **CVSS v3.1**: 6.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:H/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted XPM image file
- **外部触发路径**: gdk_pixbuf__xpm_image_load() → pixbuf_create_from_xpm() → 行 592 pointer arithmetic
- **描述**: 在 `pixbuf_create_from_xpm()` 中，行 592 执行 `pixtmp = pixbuf->pixels + ycnt * pixbuf->rowstride`，其中 `ycnt` 和 `pixbuf->rowstride` 均为 `gint`（32-bit signed int）。当 `w = 268435456`（2^28）且 `is_trans = TRUE`（RGBA，4 通道）时，`gdk_pixbuf_new` 会计算 `rowstride = 268435456 * 4 = 1073741824`（恰好 < INT_MAX，通过 gdk_pixbuf_new 的溢出检查），并成功分配 `h * 1073741824` 字节。当 `ycnt = 2` 时，`ycnt * pixbuf->rowstride = 2 * 1073741824 = 2147483648 = INT_MIN`，发生有符号整数溢出（未定义行为，实际结果为 −2147483648）。该负值被 sign-extend 为 64-bit `ptrdiff_t`，使 `pixtmp = pixels − 2GB`，指向分配缓冲区之前约 2 GB 处。随后的像素写循环（行 608-615）向该越界地址写入最多约 1 GB 像素数据，造成堆缓冲区越界写。
- **触发条件**: 攻击者构造 XPM 文件，头部声明 `width=268435456 height=3 ncolors=1 cpp=1`，颜色映射含一个透明色（使 `is_trans=TRUE`），三行像素数据各至少含 268435456 个字符（约 268 MB/行，总文件约 800 MB+）。目标系统需能分配约 3 GB 连续内存（64-bit 系统、内存充足时可满足）。
- **安全影响**: 越界写操作击中堆分配基址前约 2 GB 处的内存。若该区域为其他堆对象，攻击者可借助精心布局实现任意堆数据覆盖，最差情况为远程代码执行（RCE）；因目标内存通常为未映射区域，常见结果为进程崩溃（DoS / SIGSEGV）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
