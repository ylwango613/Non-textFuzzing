### CVE-Candidate: Heap OOB Read via Unbounded `rle_buffer` in `gdk_pixbuf_from_pixdata()`

**Severity:** High | **CWE:** CWE-125 (Out-of-bounds Read) | **CVSS v3.1:** 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)

---

**漏洞描述 / Description**

`gdk-pixdata.c` 中的 `gdk_pixbuf_from_pixdata()` 函数在 RLE 解码循环中，仅以输出缓冲区上界（`image_limit`）约束 `rle_buffer` 指针的推进，未对输入像素数据的边界进行校验。攻击者可构造 `.gdkp` 文件，声明大尺寸图像但仅提供极少字节的 RLE 输入，当输入数据耗尽而输出循环仍在继续时，`rle_buffer` 指针越界读取相邻堆内存。越界读取可泄露堆上敏感数据（如指针、密钥），亦可因访问未映射内存导致进程崩溃（DoS）。

In `gdk_pixbuf_from_pixdata()` (`gdk-pixdata.c:454–494`), the RLE decode loop advances `rle_buffer` bounded only by the output limit (`image_buffer < image_limit`), never against the end of the input `pixdata->pixel_data`. A crafted `.gdkp` file declaring a large image (e.g. 100×100) with only a handful of RLE bytes passes `gdk_pixdata_deserialize()` validation, then causes unbounded heap reads past the input buffer, potentially leaking adjacent heap contents (pointers, keys) or crashing the process.

---

**触发方式 / Trigger**

恶意 `.gdkp` 文件经 `io-pixdata.c:try_load()` → `gdk_pixdata_deserialize()` → `gdk_pixbuf_from_pixdata()` 路径触发，可通过以下命令行复现：

```bash
gdk-pixbuf-pixdata <poc.gdkp> /tmp/out.png
# 或通过任何调用 gdk_pixbuf_new_from_file() 的应用程序加载恶意文件
```

PoC 文件位于：`_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c/002/`

---

**PoC 验证状态 / PoC Status**

| 项目 | 状态 |
|------|------|
| 验证状态 | ✅ `VERIFIED_CRASH` |
| PoC 编号 | 002 |
| PoC 路径 | `/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf_c/` |
| 崩溃类型 | Heap OOB Read（输入边界越界） |
