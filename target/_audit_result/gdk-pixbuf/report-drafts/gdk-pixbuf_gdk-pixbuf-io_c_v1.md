### GdkPixdata RAW Decoder Heap Out-of-Bounds Read via Unchecked `rowstride * height` Against Stream Length

| 字段 / Field | 值 / Value |
|---|---|
| **严重程度 / Severity** | High |
| **CWE** | CWE-125 (Out-of-bounds Read) |
| **CVSS v3.1** | 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H) |
| **受影响组件 / Affected Component** | `gdk_pixdata_deserialize()` / `gdk_pixbuf_from_pixdata()` — `gdk-pixdata.c:235, 506` |

**漏洞描述（中文）**

`gdk_pixdata_deserialize()` 在 line 235 的边界检查仅将流总长度与头部字段 `pixdata->length` 对比，但 `gdk_pixbuf_from_pixdata()` 在 RAW 编码路径（line 506）实际以 `rowstride * height` 为长度执行 `memcpy`，而该值从未与真实可用字节数校验。攻击者可将 `pixdata->length` 设为最小合法值 24，使 line 235 的检查形同虚设，同时将 `rowstride * height` 设为任意大值，令 `memcpy` 从仅有 0 有效字节的 `pixel_data` 向外越界读取堆内存。此漏洞可导致堆上敏感数据泄露（密钥、ASLR 地址等）或进程崩溃（DoS）。

**Vulnerability Description (English)**

`gdk_pixdata_deserialize()` validates stream bounds only against the header-declared `pixdata->length` field (line 235), but `gdk_pixbuf_from_pixdata()` copies `rowstride * height` bytes via `memcpy` (line 506) without ever checking whether that product exceeds the actual available bytes in the stream. By setting `pixdata->length = 24` (minimum valid value, making the bounds check evaluate as `stream_length < 0` → always false) while setting `rowstride * height` to an arbitrarily large value, an attacker causes `memcpy` to read far beyond the zero valid pixel bytes, leaking heap memory contents or triggering a crash.

**触发方式 / Trigger**

构造一个畸形 `.gdkp` 文件，写入如下字段：`magic=GdkP`, `length=24`, `pixdata_type=RGB|RAW`, `rowstride=10000`, `width=10`, `height=100`，然后通过任意调用 `gdk_pixbuf_new_from_file()` 的应用加载该文件（如 `gdk-pixbuf-pixdata` 命令行工具）：

```bash
# 使用 gdk-pixbuf-pixdata 触发（将 poc.gdkp 输入 pixdata 解码路径）
gdk-pixbuf-pixdata poc.gdkp /dev/null
# 或通过 gdk-pixbuf-thumbnailer
gdk-pixbuf-thumbnailer -s 64 poc.gdkp /tmp/out.png
```

**PoC 验证状态 / PoC Status**

| 项目 | 状态 |
|---|---|
| 验证状态 | `VERIFIED_CRASH` |
| PoC 编号 | 001 |
| PoC 路径 | `/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-io_c` |
| 崩溃类型 | 堆越界读 / Heap OOB Read（SIGSEGV 或数据泄露）|
