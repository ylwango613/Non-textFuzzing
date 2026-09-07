I have completed my full analysis. Here is the final audited finding:

## VULN: Integer overflow in mmap bounds check → OOB read in TIFFReadRawStrip1
- **漏洞类别**: memory-safety
- **函数**: TIFFReadRawStrip1()
- **行号**: 198-209 (tif_read.c), 触发路径入口在 tiffinfo.c:380-424 (TIFFReadRawData)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffinfo main() [-r flag sets rawdata=1] → tiffinfo() → TIFFReadRawData(tif, 0) → TIFFReadRawStrip(tif, s, buf, stripbc[s]) → TIFFReadRawStrip1(tif, strip, buf, bytecount, module) [isMapped(tif)==true mmap path] → integer overflow in `td->td_stripoffset[strip] + size > tif->tif_size` → bypass → `_TIFFmemcpy(buf, tif->tif_base + td->td_stripoffset[strip], size)` OOB read
- **描述**: 在 `TIFFReadRawStrip1` 的内存映射（mmap）分支（`tif_read.c:198`）中，边界检查 `td->td_stripoffset[strip] + size > tif->tif_size` 存在 uint32 整数溢出：`td->td_stripoffset[strip]`（uint32，来自 TIFF StripOffsets IFD 字段，完全受攻击者控制）与 `size`（tsize_t=int32，正值，来自 StripByteCounts）相加时，两个操作数经 C 标准算术转换均为 uint32 后进行无符号加法，若和值超过 UINT32_MAX 则回绕为小数值（可能小于 tif_size），导致越界检查被绕过。随后 `_TIFFmemcpy(buf, tif->tif_base + td->td_stripoffset[strip], size)` 从 mmap 文件区域末端之外的地址读取数据，造成越界读。`TIFFReadDirectory` 阶段不对 StripOffset 的有效性做充分校验（其 BYTECOUNTLOOKSBAD 宏自身也存在整数溢出问题导致检查失效），故恶意 StripOffset 可顺利通过目录解析到达读取阶段。
- **触发条件**: 攻击者构造 TIFF 文件，将 StripOffsets[0] 设为接近 UINT32_MAX 的值（例如 `0xFFFFF000 = 4294963200`），StripByteCounts[0] 设为一个使 `offset + bytecount mod 2^32 < tif_size` 成立的小正数（例如 4096，使得 4294963200+4096=0 mod 2^32，绕过文件大小检查）。以 `-r` 参数运行 `tiffinfo` 打开该文件（触发 TIFFReadRawData 路径），且系统使用 mmap 模式打开文件（Unix 默认行为）。文件本身可以很小（几百字节），无需包含真实的 4GB 数据。
- **安全影响**: 最坏情况下，进程在尝试读取 `tif->tif_base + ~4GB` 处的地址时发生 SIGSEGV，导致 tiffinfo 崩溃（DoS）。在内存布局特殊的场景下（mmap 基地址附近碰巧有其他可读映射），理论上可通过 `_TIFFmemcpy` 将越界内存内容复制到 `buf` 后由 `ShowRawBytes/ShowRawWords` 打印到 stdout，造成进程内存信息泄露（如栈地址、堆数据等），可辅助绕过 ASLR。

<!-- AUDIT_PROMPT_VERSION: 1 -->
