Both vulnerabilities are confirmed. Writing the final report now.

## VULN: Heap OOB Read via duplicate ICC_PROFILE APP2 segments in JPEG
- **漏洞类别**: memory-safety
- **函数**: `jpeg_parse_exif_app2_segment()`
- **行号**: 366-379
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: High
- **攻击向量**: crafted JPEG file
- **外部触发路径**: `gdk_pixbuf__jpeg_image_load()` → `jpeg_parse_exif()` → `jpeg_parse_exif_app2_segment()` (每个 APP2 marker 调用一次) → `g_base64_encode(exif_context.icc_profile, exif_context.icc_profile_size)`（行 611）
- **描述**: `jpeg_parse_exif_app2_segment` 在多块 ICC profile 路径下（`number_of_chunks != 1`），第 366–368 行仅在首次调用时分配 `number_of_chunks * 0xffff` 字节的缓冲区，第 372 行的边界检查仅验证单次写入不越界（`offset + chunk_size <= icc_profile_size_allocated`），但并未阻止累积值超限：第 379 行 `context->icc_profile_size += chunk_size` 在每次通过边界检查的调用中无条件累加。若 JPEG 文件包含 N 个 APP2 marker，均携带 `sequence_number=1, number_of_chunks=2, chunk_size=65519`，则每个 marker 的写操作都写在 offset=0 处（合法），但 `icc_profile_size` 每次增加 65519，第 3 个 marker 之后 `icc_profile_size = 3×65519 = 196557`，超过 `icc_profile_size_allocated = 2×65535 = 131070`。后续 `g_base64_encode(exif_context.icc_profile, exif_context.icc_profile_size)`（行 611 / 行 1049）以超出分配长度的 `icc_profile_size` 作为读取长度，导致堆缓冲区越界读取，泄露 `icc_profile` 分配块之后的堆内存内容。
- **触发条件**: 构造一个 JPEG 文件，在 SOI 之后插入 ≥3 个 JPEG APP2 marker（`0xFF 0xEB`），每个 marker 的数据域均以 `"ICC_PROFILE\x00"` 开头，`data[12]=0x01`（sequence_number=1），`data[13]=0x02`（number_of_chunks=2），数据域长度为 14+65519=65533 字节。无需特殊权限，任何调用 `gdk_pixbuf_new_from_file` 加载 JPEG 的应用均可被触发。
- **安全影响**: 堆越界读——泄露 `icc_profile` 分配块之后的任意堆内存（最多可泄露 `N×65519 − 131070` 字节，N 为重复 marker 数量），可能包含堆指针、函数指针或其他敏感数据，可用于信息泄露（绕过 ASLR），为进一步利用铺路；大量 marker 时可能触发 SIGSEGV，造成 DoS。

## VULN: Heap OOB Read in real_save_jpeg ICC profile write loop (off-by-one)
- **漏洞类别**: memory-safety
- **函数**: `real_save_jpeg()`
- **行号**: 1374-1388
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.3 (AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted JPEG file（通过 ICC profile round-trip）
- **外部触发路径**: 攻击者提供含大型 ICC profile 的 JPEG → 应用调用 `gdk_pixbuf_new_from_file()` 加载（产生含 `"icc-profile"` 选项的 pixbuf）→ 应用调用 `gdk_pixbuf_save(..., "icc-profile", ...)` → `real_save_jpeg()` 行 1273 `g_base64_decode` 还原 ICC 数据 → 行 1374–1388 的 ICC 分块写入循环越界读取
- **描述**: 当解码后的 ICC profile 长度 `icc_profile_size >= 0xffef`（65519）且不能被 `0xffef` 整除时，行 1374 计算 `segments = ceil(icc_profile_size / 0xffef)`，行 1375 分配 `data = g_new(gchar, 0xffff)`。循环条件 `i <= segments`（行 1378）使循环比预期多执行一次（共 `segments+1` 次迭代，而非 `segments` 次）：(1) 当 `i = segments-1`：`size` 仍为 `0xffef`，`offset = 0xffef*(segments-1)`，从 `icc_profile + offset` 处读取完整的 `0xffef` 字节，但此处实际只剩 `icc_profile_size % 0xffef` 字节有效，越界读取最多 `0xffef-1` 字节的堆内存；(2) 当 `i = segments`（额外迭代）：`size = icc_profile_size % 0xffef`，`offset = 0xffef * segments >= icc_profile_size`，从完全超出 `icc_profile` 缓冲区末端的地址读取 `size` 字节。
- **触发条件**: 攻击者提供一个 JPEG，其内嵌 ICC profile 解码后大小 ≥ 65519 字节且不被 65519 整除（如 65520 字节）；目标应用需在加载该 JPEG 后，将 pixbuf 的 `"icc-profile"` 选项直接传入 `gdk_pixbuf_save()`（常见的 transcoding 或格式转换场景）。
- **安全影响**: 堆越界读——`icc_profile` 缓冲区末端之后的堆内存通过 `memcpy` 被复制至 `data` 并经 `jpeg_write_marker` 写入输出 JPEG，造成堆内存信息泄露（输出文件中可包含任意堆数据），可用于信息泄露；在极端情况下若越界地址跨越页边界则触发 SIGSEGV 造成 DoS。

<!-- AUDIT_PROMPT_VERSION: 1 -->
