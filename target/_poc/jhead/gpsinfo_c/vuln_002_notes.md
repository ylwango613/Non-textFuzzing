# VULN 002 – GPS strncpy Missing Null-Termination (CWE-170)

## PoC 思路

构造一个 JPEG，其 EXIF 数据中包含 GPS IFD，其中 GPS Latitude 的三个 URATIONAL
分量均使用分母 = 1,000,000，以触发 `ProcessGpsInfo()` 中的如下逻辑缺陷。

## 触发路径

```
main() -> ReadJpegFile() -> process_EXIF() -> ProcessExifDir()
       -> ProcessGpsInfo() -> strncpy(ImageInfo.GpsLat+2, TempString, 29)
```

## digits 计算

```c
den = 1000000;
digits = 0;
while (den > 1 && digits <= 6) { den /= 10; digits++; }
// 6 次迭代后 den=1，digits=6
```

## FmtString 变化

初始值：`"%0.0fd %0.0fm %0.0fs"`
最终值：`"%9.6fd %9.6fm %9.6fs"`（每分量宽度9，6位小数）

## snprintf 输出

数值 89.0° / 59.0′ / 59.0″ → `"89.000000d 59.000000m 59.000000s"` (32 字符)

## strncpy 缺陷

```c
strncpy(ImageInfo.GpsLat+2, TempString, 29);
```
- `TempString` 长度 32 >= n=29：strncpy 复制 29 字节但**不追加 '\0'**
- `GpsLat[30]` 被写为 `'0'`（非零）
- `GpsLat[31]` 依赖全局零初始化（BSS）维持 `'\0'`

## 预期现象

- jhead 输出中 GPS Latitude 字段显示为截断的坐标字符串（31 字符）
- ASAN/UBSAN 可能不产生直接 crash（取决于 GpsLat[31] 初始状态）
- 若处理多个文件，GpsLat[31] 可能非零，printf 会越界读取相邻结构体字段
  导致信息泄漏（如 GpsLong 内容）

## 关键 EXIF 字节布局

```
TIFF base offset 0:
  [0 -  7] TIFF header (II, 0x002A, IFD0@8)
  [8 - 25] IFD0: 1 entry, GPS IFD pointer (tag=0x8825) -> offset 26
  [26- 79] GPS IFD: 4 entries
             LatRef  (0x0001): "N\0" inline
             Lat     (0x0002): URATIONAL x3, data@80
             LonRef  (0x0003): "E\0" inline
             Lon     (0x0004): URATIONAL x3, data@104
  [80-103] Lat data: (89000000/1000000, 59000000/1000000, 59000000/1000000)
  [104-127] Lon data: (120000000/1000000, 30000000/1000000, 45000000/1000000)
```
