Confirmed both OOB reads. Writing the final report.

## VULN: Heap OOB Read in LogLuvDecode24 Due to Insufficient Raw-Buffer Guard
- **漏洞类别**: memory-safety
- **函数**: LogLuvDecode24()
- **行号**: 262-266
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → TIFFReadEncodedStrip() → LogLuvDecodeStrip() → LogLuvDecode24()
- **描述**: `LogLuvDecode24` 解码 SGILOG24 压缩像素时，外层循环守卫仅检查 `cc > 0`（第 262 行），而循环体内每次固定读取 **3 字节**（`bp[0]`, `bp[1]`, `bp[2]`，第 263 行）。若 `cc = 1` 则 `bp[1]` 和 `bp[2]` 越界（超出 `tif_rawdata` 末端 1–2 字节）；若 `cc = 2` 则 `bp[2]` 越界（超出末端 1 字节）。越界读到的堆字节会被 OR 合并进 `tp[i]`（像素值），并最终由 `sp->tfunc`（`Luv24toXYZ` 等）写入调用方输出缓冲区，再被 tiffsplit 写入磁盘上的输出 TIFF。攻击者可通过观察输出文件中的像素值反推出堆内存内容，实现 heap info leak。
- **触发条件**: 攻击者构造一个 TIFF 文件：Photometric = PHOTOMETRIC_LOGLUV，Compression = COMPRESSION_SGILOG24，至少一个 strip 的 `StripByteCount` 设为 1 或 2（从而 `tif->tif_rawcc < 3`），strip 数据中包含任意有效字节。这些条件完全处于攻击者对 TIFF 文件的控制范围内，无需特殊权限。
- **安全影响**: 攻击者通过 tiffsplit 处理精心构造的输入后，可从输出 TIFF 文件中读取到 1–2 字节堆内存（越界读取内容经解码路径流入输出），可用于信息泄露（披露 heap 元数据或相邻缓冲区内容），辅助 ASLR bypass，最坏情况下是内存信息泄露 (C:H when treating heap leak as sensitive) 和轻微拒绝服务（处理函数返回错误）。

## VULN: Heap OOB Read in LogL16Decode Run-Length Branch When cc=1
- **漏洞类别**: memory-safety
- **函数**: LogL16Decode()
- **行号**: 210-214
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → TIFFReadEncodedStrip() → LogLuvDecodeStrip() → LogL16Decode()
- **描述**: `LogL16Decode` 在解码 SGILOG 游程压缩数据时，外层 for 循环守卫为 `cc > 0`（第 210 行）。当 `cc = 1`（raw buffer 剩余 1 字节）且该字节 ≥ 128 进入 run 分支时，代码连续执行两次 `*bp++`：第一次（`rc = *bp++ + (2-128)`）读取唯一有效字节，第二次（`b = (int16)(*bp++ << shft)`，第 213 行）读取的是 **raw buffer 末端后 1 字节**（堆越界读）。越界读到的字节值被强制转换为 `int16` 并存入 `b`，随后在 `tp[i++] |= b`（第 216 行）中被 OR 写入输出像素缓冲区，最终由 tiffsplit 写入磁盘。攻击者可通过输出文件恢复该越界字节的值。
- **触发条件**: 攻击者构造 TIFF：Photometric = PHOTOMETRIC_LOGL，Compression = COMPRESSION_SGILOG，某 strip 的 `StripByteCount = 1`，该 1 字节 strip 数据 ≥ 0x80（即 128）进入 run 分支。所有字段均处于攻击者对 TIFF 文件格式的控制范围内。
- **安全影响**: 堆越界读出的 1 字节被嵌入输出图像的像素数据中，通过 tiffsplit 写入输出文件，导致 heap 信息泄露（heap metadata 或相邻分配块内容暴露）；可辅助绕过 ASLR；在 NDEBUG（release）编译下不存在 assert 中断，漏洞完全可达。

## VULN: Heap OOB Read in LogLuvDecode32 Run-Length Branch When cc=1
- **漏洞类别**: memory-safety
- **函数**: LogLuvDecode32()
- **行号**: 310-314
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.0 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:L)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadDirectory() → TIFFReadEncodedStrip() → LogLuvDecodeStrip() → LogLuvDecode32()
- **描述**: `LogLuvDecode32` 与 `LogL16Decode` 存在同一类型漏洞：外层循环守卫为 `cc > 0`，run 分支（`*bp >= 128`）无条件连续读取 2 字节（第 312–313 行：`rc = *bp++` 和 `b = (uint32)*bp++ << shft`），但未先验证 `cc >= 2`。当 `tif->tif_rawcc = 1` 且攻击者将该单字节设为 ≥ 128 时，第 313 行的 `*bp++` 读取 raw buffer 末端后 1 字节（heap OOB read）。该字节值经 `(uint32)byte << shft` 后与 `tp[i]` OR 运算写入输出缓冲区，再由 tiffsplit 写入输出 TIFF 文件，形成 heap 信息泄露路径。此漏洞发生在 4 次 shft 迭代（`shft` 取 24、16、8、0）中的任意一次，即在单次 `LogLuvDecodeStrip` 调用中最多可能泄露 4 字节（若 4 次迭代均命中该路径）。
- **触发条件**: 攻击者构造 TIFF：Photometric = PHOTOMETRIC_LOGLUV，Compression = COMPRESSION_SGILOG（32 位），某 strip 的 `StripByteCount = 1`，1 字节 strip 数据 ≥ 0x80。无需特殊权限，条件完全由攻击者控制。
- **安全影响**: 每次调用最多泄露 4 字节堆内存（经 OR 编码嵌入像素输出文件），可用于信息泄露和 ASLR 辅助绕过；拒绝服务影响较轻（处理返回错误但进程不崩溃）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
