### CVE-Pending: Heap Buffer Overflow via RLE Zero-Length Repeat-Run in `gdk_pixbuf_from_pixdata`

| 字段 | 值 |
|------|-----|
| **Severity** | Critical |
| **CWE** | CWE-122 (Heap-based Buffer Overflow) |
| **CVSS v3.1** | 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H) |
| **Component** | gdk-pixbuf — `gdk-pixdata.c:gdk_pixbuf_from_pixdata()` L463–483 |

#### 漏洞描述 / Description

**（中文）** `gdk_pixbuf_from_pixdata()` 在解码 RLE 压缩像素数据时，若 repeat-run 字节值为 `0x80`，则计算得 `length = 0`（`guint` 类型）。边界检查因步长为 0 而不触发，随后进入 do-while 循环的第一次写入后执行 `--length`，导致无符号下溢：`0 - 1 = UINT_MAX ≈ 4.29×10⁹`，循环继续约 42 亿次，每次向堆缓冲区写入 3–4 字节，总写入量约 12–17 GB，远超分配边界，覆盖相邻堆对象。

**（English）** When `gdk_pixbuf_from_pixdata()` processes an RLE repeat-run byte of `0x80`, the computed `length` (type `guint`) becomes `128 − 128 = 0`. The bounds check passes silently (zero-stride is not flagged), and the subsequent `--length` in the do-while loop wraps to `UINT_MAX` (~4.29 billion), causing the loop to iterate ~4 billion times and write up to ~17 GB into a heap buffer whose actual size is only `height × rowstride` bytes. This corrupts adjacent heap objects and can lead to RCE or DoS.

#### 触发方式 / Trigger

构造包含 `0x80` 字节的 RLE 编码 GdkPixdata 文件（magic `GdkP`，`pixdata_type` 设为 `GDK_PIXDATA_ENCODING_RLE`），通过以下命令触发：

```bash
# 方式一：gdk-pixbuf-pixdata 工具直接解析
gdk-pixbuf-pixdata <crafted.gdkp>

# 方式二：通用图像加载路径（间接触发）
gdk-pixbuf-view <crafted.gdkp>
# 或任何调用 gdk_pixbuf_new_from_file() 的应用
```

调用链：`io-pixdata.c:pixdata_image_stop_load()` → `try_load()` → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` → **堆溢出**

#### PoC 验证状态 / PoC Status

| 项目 | 状态 |
|------|------|
| **验证结果** | `VERIFIED_CRASH` |
| **PoC 编号** | 001 |
| **PoC 路径** | `/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c/` |
