### CVE-Candidate: Heap Buffer Overflow via Zero-Length Constant Run in GdkPixdata RLE Decoder

| 字段 | 值 |
|---|---|
| **Severity** | High |
| **CWE** | CWE-122 (Heap-based Buffer Overflow) |
| **CVSS v3.1** | 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Component** | gdk-pixbuf — `gdk_pixbuf_from_pixdata()` (gdk-pixdata.c:462–483) |
| **PoC Status** | VERIFIED_CRASH |

---

**漏洞描述（中文）**

`gdk_pixbuf_from_pixdata()` 的 RLE 解码循环中，当解析到游程长度字节 `0x80`（有效长度 = 0x80 − 128 = 0）时，越界检查 `check_overrun` 计算为 `FALSE`，length 未被截断。随后进入 `do { memcpy(...); image_buffer += bpp; } while (--length)` 循环：首次迭代结束后 `--length` 发生无符号整数下溢变为 `UINT_MAX`，循环约执行 2³² 次，持续向堆写入攻击者可控数据。在 32 位系统上可覆盖任意堆内存（堆元数据、函数指针），具有远程代码执行（RCE）潜力；在 64 位系统上快速越界导致崩溃（DoS）。

**Vulnerability Description (English)**

In the RLE decoder of `gdk_pixbuf_from_pixdata()`, a crafted constant-run length byte `0x80` yields an effective length of zero, causing the bounds check to pass silently. The subsequent `do-while` loop decrements an unsigned `length` from 0 to `UINT_MAX`, iterating ~2³² times and writing attacker-controlled bytes continuously into the heap. This results in arbitrary heap corruption (potential RCE on 32-bit) or a rapid out-of-bounds crash (DoS on 64-bit).

---

**触发方式 / Trigger**

构造包含字节 `0x80` 游程条目的 GdkPixdata 二进制文件（魔数 `GdkP`，pixdata_type = `RGBA|RLE|SAMPLE_WIDTH_8`），通过以下命令触发：

```bash
# 触发路径
gdk-pixbuf-csource --raw /path/to/crafted.gdkp

# 完整调用链
gdk-pixbuf-csource → gdk_pixbuf_new_from_file()
  → io-pixdata.c: pixdata_image_stop_load()
  → gdk_pixdata_deserialize()
  → gdk_pixbuf_from_pixdata()   ← 漏洞触发点 (gdk-pixdata.c:462)
```

---

**PoC 验证**

| 项目 | 详情 |
|---|---|
| **状态** | `VERIFIED_CRASH` |
| **PoC 编号** | 001 |
| **PoC 路径** | `/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c/` |
