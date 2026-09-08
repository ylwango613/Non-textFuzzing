### CVE-Candidate: Heap Buffer Overflow via RLE Control Byte 0x80 in `gdk_pixbuf_from_pixdata`

| 字段 | 值 |
|------|-----|
| **Severity** | High |
| **CWE** | CWE-787 (Out-of-bounds Write) |
| **CVSS v3.1** | 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Component** | `gdk-pixdata.c`, function `gdk_pixbuf_from_pixdata()`, lines 463–483 |
| **PoC Status** | VERIFIED_CRASH |

---

**漏洞描述（中文）**

在 `gdk_pixbuf_from_pixdata()` 的 RLE 解码循环中，当游程控制字节为 `0x80` 时，`length = 0x80 - 128 = 0`（`guint` 类型）。由于越界检查 `check_overrun` 结果为 FALSE，length 不被截断；随后的 `do-while` 循环至少执行一次，`--length` 对无符号零值下溢为 `UINT_MAX`（4294967295），导致约 42 亿次 `memcpy` 写操作迅速溢出仅按 `rowstride*height` 分配的堆缓冲区。攻击者可通过构造恶意 pixdata 字节流触发堆越界写入，轻则造成进程崩溃（DoS），结合堆风水布局可升级为任意代码执行（RCE）。

**Vulnerability Description (English)**

In the RLE decode loop of `gdk_pixbuf_from_pixdata()`, a control byte of `0x80` yields `length = 128 − 128 = 0` as a `guint`. The bounds check evaluates to FALSE and does not clamp the value; the subsequent `do-while` loop executes at least once, after which `--length` underflows from zero to `UINT_MAX` (4,294,967,295), triggering billions of `memcpy` writes that immediately overflow the heap buffer allocated as `rowstride × height` bytes. The missing zero-length guard—present elsewhere in the same file at `pixdata_get_length()` lines 68–71 but absent here—allows heap metadata corruption, leading to DoS or potential RCE.

---

**触发方式**

```bash
# 构造最小化 PoC 文件（24 字节头 + pixel_data[0]=0x80）
# pixdata_type=RLE, width=1, height=1, rowstride=3

gdk-pixbuf-pixdata <poc_001.pixdata> /dev/null
# 或通过 gdk_pixbuf_new_from_inline() 加载内联数据触发同一路径
```

PoC 路径：`/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-pixdata_c/001`

---

**PoC 验证状态**：`VERIFIED_CRASH` — 已在目标版本上复现堆越界写入并确认崩溃。
