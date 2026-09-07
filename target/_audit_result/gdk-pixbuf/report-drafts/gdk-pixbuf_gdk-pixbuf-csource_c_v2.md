### Out-of-Bounds Heap Read via Missing `rle_buffer` Bounds Check in GdkPixdata RLE Decoder

**Severity:** High | **CWE:** CWE-125 (Out-of-bounds Read) | **CVSS v3.1:** 7.5 (AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H)

**Component:** `gdk_pixbuf_from_pixdata()` — `gdk-pixdata.c:452–503`

---

#### Vulnerability Description | 漏洞描述

`gdk_pixbuf_from_pixdata()` 中的 RLE 解码循环以输出缓冲区指针 `image_buffer < image_limit` 作为唯一终止条件，从不验证读取指针 `rle_buffer` 是否仍在 `pixel_data` 范围内。当精心构造的 GdkPixdata 文件声明了远大于实际 RLE 编码数据能产生的输出字节数时，`rle_buffer` 会在 `image_buffer` 到达 `image_limit` 之前越出 `pixel_data` 末端，读取堆上相邻内存。此漏洞可导致敏感堆数据泄露（信息泄露）或读取未映射内存页引发崩溃（DoS）。

The RLE decode loop in `gdk_pixbuf_from_pixdata()` terminates solely on the output-buffer condition `image_buffer < image_limit`, with no corresponding check that `rle_buffer` remains within the bounds of `pixel_data`. A crafted `.gdkp` file can cause `rle_buffer` to read past the end of the heap-allocated pixel data before the output buffer is filled, resulting in an out-of-bounds heap read. Impact includes heap memory disclosure (information leak) and potential crash (DoS) if an unmapped page is reached.

---

#### Trigger Method | 触发方式

```bash
# 构造 .gdkp 文件：pixdata_type=RLE|RGBA，声明大量输出字节，
# 但实际 pixel_data 中的 RLE 序列极短，无法填满输出缓冲区
gdk-pixbuf-csource poc_002.gdkp
# 或等效路径：
gdk-pixbuf-pixdata --decode poc_002.gdkp /dev/null
```

外部调用链：`gdk-pixbuf-csource input.gdkp` → `gdk_pixbuf_new_from_file()` → `io-pixdata` loader → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` → RLE decode OOB read

---

#### PoC Verification Status | PoC 验证状态

| 状态 | 详情 |
|------|------|
| **VERIFIED_CRASH** | 已通过构造 PoC 文件复现崩溃 |
| PoC 目录 | `/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c` |
| PoC 编号 | `002` |
