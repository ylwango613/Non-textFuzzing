### CVE-Candidate: Off-by-Header-Length Integer Check in `gdk_pixdata_deserialize` Enables Truncated-Stream Attacks

**严重程度 / Severity:** Medium
**CWE:** CWE-131 (Incorrect Calculation of Buffer Size)
**CVSS v3.1:** 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)

---

**漏洞描述（中文）**

`gdk-pixdata.c` 第 235 行的流长度校验逻辑存在差一错误：条件写为 `stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH`，比正确的 `stream_length < pixdata->length` 宽松 24 字节（即头部长度）。攻击者可构造总字节数落在 `[pixdata->length - 24, pixdata->length - 1]` 区间内的恶意 `.gdkp` 文件，使截断检查静默通过。后续 `gdk_pixbuf_from_pixdata()` 按头部声明的 `height × rowstride` 驱动 RLE 解码，但可读的 `pixel_data` 已被截断，导致越界读取，可引发堆信息泄露或进程崩溃（DoS）。

**Vulnerability Description (English)**

A length check at line 235 of `gdk-pixdata.c` uses `stream_length < pixdata->length - GDK_PIXDATA_HEADER_LENGTH` instead of the correct `stream_length < pixdata->length`, making the guard 24 bytes too permissive. A crafted `.gdkp` stream whose total size lies in the range `[pixdata->length - 24, pixdata->length - 1]` silently passes the check. The downstream RLE decoder in `gdk_pixbuf_from_pixdata()` then reads beyond the truncated `pixel_data` buffer (driven by the attacker-controlled `height × rowstride` fields), leading to an out-of-bounds read that can leak heap contents or crash the process.

---

**触发方式 / Trigger**

```bash
# 构造 pixdata->length = stream_length + K（1 ≤ K ≤ 24）的恶意文件
gdk-pixbuf-csource poc_003.gdkp
# 或通过 gdk-pixbuf-pixdata 加载路径
gdk-pixbuf-pixdata --rle poc_003.gdkp
```

完整外部调用链：`gdk-pixbuf-csource input.gdkp` → `gdk_pixbuf_new_from_file()` → io-pixdata loader → `gdk_pixdata_deserialize()` (length check bypassed) → `gdk_pixbuf_from_pixdata()` (OOB read)

---

**PoC 验证状态 / PoC Status**

| 字段 | 值 |
|---|---|
| 状态 | **VERIFIED_CRASH** |
| PoC 编号 | 003 |
| PoC 路径 | `/data/ylwang/non-textfuzz/target/_poc/gdk-pixbuf/gdk-pixbuf_gdk-pixbuf-csource_c` |
| 影响函数 | `gdk_pixdata_deserialize()` @ `gdk-pixdata.c:235` |
