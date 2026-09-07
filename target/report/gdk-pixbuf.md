# gdk-pixbuf Vulnerabilities

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf_c_v2 -->
<!-- DEDUP: `gdk_pixbuf_from_pixdata::CWE-125 -->
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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf_c_v1 -->
<!-- DEDUP: `gdk_pixbuf_from_pixdata::CWE-122 -->
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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-csource_c_v3 -->
<!-- DEDUP: gdk_pixdata_deserialize::CWE-131 -->
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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-csource_c_v1 -->
<!-- DEDUP: gdk_pixbuf_from_pixdata::CWE-122 -->
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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-csource_c_v2 -->
<!-- DEDUP: gdk_pixbuf_from_pixdata::CWE-125 -->
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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-io_c_v1 -->
<!-- DEDUP: `gdk_pixdata_deserialize::CWE-125 -->
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

<!-- REPORT_SOURCE: gdk-pixbuf_gdk-pixbuf-pixdata_c_v1 -->
<!-- DEDUP: gdk_pixbuf_from_pixdata::CWE-787 -->
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
