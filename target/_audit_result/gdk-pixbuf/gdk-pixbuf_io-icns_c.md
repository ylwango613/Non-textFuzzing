Now I have full context. Let me analyze both vulnerabilities carefully before writing the final report.

**Analysis of VULN 1 — Integer underflow in `load_resources()`:**
- `blocklen` is `guint32` from file. The while-loop only ensures `remaining >= sizeof(IcnsBlockHeader)` (8) and `blocklen <= remaining`. No lower bound ensures `blocklen >= sizeof(IcnsBlockHeader)`.
- When `blocklen = 4` (< 8): `*plen = blocklen - sizeof(IcnsBlockHeader) = 4 - 8` → wraps to `~0xFFFFFFFFFFFFFFFC` (gsize on 64-bit).
- For 256-size path: `gdk_pixbuf_loader_write(loader, icon, isize=~18EB, NULL)` → massive OOB heap read → crash.
- For 128/48/32/16-size paths: `isize` hugely overflow → uncompress OOB read path.

**Analysis of VULN 2 — OOB read in `uncompress()`:**
- `uncompress()` reads from `data` pointer with no source-length bound. It only stops when `size*size` output pixels are produced.
- The 3-pass call (R, G, B channels) means `data` advances across all three RLE streams sequentially.
- If the it32/ih32/il32/is32 block is placed last in the ICNS file with only R-channel RLE data, after the first `uncompress()` call `data` reaches end of buffer. The G-channel call reads `data[0]` past the end of the heap-allocated `GByteArray` → heap over-read.
- No `count` or `data` bounds-against-source-size checking anywhere in the function.

## VULN: Integer Underflow in blocklen → Heap Over-Read via gdk_pixbuf_loader_write
- **漏洞类别**: memory-safety
- **函数**: load_resources()
- **行号**: 84-98 (underflow), 251 (exploitation)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted .icns image file
- **外部触发路径**: icns_image_load() → load_icon(256, …) → load_resources() [*plen underflow] → gdk_pixbuf_loader_write(loader, icon, isize≈18EB, NULL) [OOB read]
- **描述**: In `load_resources()`, `blocklen` is read directly from the attacker-controlled file as a big-endian `guint32`. The while-loop guard (line 81) only ensures the *remaining* bytes ≥ `sizeof(IcnsBlockHeader)` = 8, and the check at line 87 only ensures `blocklen ≤ remaining`—neither enforces a *minimum* of 8. When an attacker sets `blocklen = 4` (legal per those two checks), the assignment `*plen = blocklen - sizeof(IcnsBlockHeader)` = `4 − 8` underflows the unsigned `gsize` to `~0xFFFFFFFFFFFFFFFC` (≈18 exabytes on 64-bit). For size-256 icons (ic08/ic09), this value is passed verbatim as the `count` argument to `gdk_pixbuf_loader_write(loader, icon, isize, NULL)`, directing the loader to read ~18 EB from a heap pointer that has at most a few valid bytes remaining, causing an immediate heap buffer over-read.
- **触发条件**: 构造一个 ICNS 文件，其中 "ic08"（256×256）块的 `size` 字段（big-endian uint32）被设置为小于 8 的值（如 4）。该文件只需约 20 字节即可触发漏洞，无需任何有效的 JPEG 2000 图像数据。
- **安全影响**: 确定性崩溃（DoS）；堆内存大量越界读取还可能造成堆布局信息泄露（ASLR bypass 辅助），在特定 allocator 实现下理论可被链式利用为 RCE 前置。

## VULN: Heap Over-Read in uncompress() Due to Missing Source Bounds Check
- **漏洞类别**: memory-safety
- **函数**: uncompress()
- **行号**: 176-229 (missing check), 284-295 (call site)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.5 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted .icns image file
- **外部触发路径**: icns_image_load() → load_icon(128/48/32/16, …) → load_resources() → uncompress() [reads data[0] past end of heap buffer]
- **描述**: `uncompress()` RLE-decompresses one color channel at a time. It tracks how many *output* pixels remain (`remaining = size*size`) but has **no source-length parameter** and performs zero bounds checking on the `data` source pointer. The function reads `data[0]` (and up to `data[count]` in the non-repeating branch) each iteration until all `size*size` pixels are written. `load_icon()` calls `uncompress()` three consecutive times for R, G, and B channels, advancing the shared `data` pointer across all three. If an attacker places the icon block (e.g., "it32" for 128×128) at the end of the ICNS file and includes only enough compressed bytes to cover the R channel (e.g., 254 bytes of max-efficiency RLE), the G-channel `uncompress()` call starts with `data` pointing exactly at `bytes + icnslen` (end of the `GByteArray` allocation). The first `data[0]` access in that call reads one byte past the allocated heap buffer, and subsequent reads continue further OOB for the remaining ~32,768 pixels of G+B channels, constituting a heap buffer over-read of up to several kilobytes past the allocation boundary.
- **触发条件**: 构造一个 ICNS 文件，包含 it32（128×128）块（放置在文件末尾），t8mk mask 块（16384 字节），其中 it32 块的 RLE 压缩数据量仅足以解压 R 通道的 16384 像素而不足以继续 G/B 通道，且 it32 块是文件中最后一个 block。当 `uncompress()` 为 G 通道被调用时，`data` 指针已位于 GByteArray 堆分配末端。
- **安全影响**: 堆越界读取（最多数 KB），必然导致进程崩溃（DoS）；若 allocator 在该区域未分配额外 guard 页，读取数据可能泄露相邻堆对象内容（信息泄露），辅助更复杂的漏洞利用链。

<!-- AUDIT_PROMPT_VERSION: 1 -->
