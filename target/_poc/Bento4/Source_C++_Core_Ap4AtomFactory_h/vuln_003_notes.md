# VULN 003 – AP4_SaioAtom Integer Overflow PoC Notes

## 漏洞概要

- **组件**: Bento4 / `AP4_SaioAtom::AP4_SaioAtom()`
- **类型**: 32-bit 整数溢出 → bounds check 绕过 → Heap OOB / std::bad_alloc
- **CVE**: N/A (内部编号 VULN 003)

## 触发路径

```
mp42aac input.mp4
  → AP4_AtomFactory::CreateAtomFromStream()
  → AP4_SaioAtom::Create(size, stream)
  → new AP4_SaioAtom(size, version, flags, stream)
```

## 根因分析

`AP4_SaioAtom` 构造函数读取 `entry_count`（32-bit），然后用
`entry_count * (version == 0 ? 4 : 8)` 计算需要读取的字节数，并与剩余可用字节数对比做 bounds check。

当 `version = 1` 且 `entry_count = 0x20000000` 时：

```
0x20000000 * 8 = 0x100000000  (33-bit)
```

若该乘法结果以 32-bit unsigned 截断则为 `0`，bounds check 条件

```cpp
if (remains < (AP4_Size)(entry_count * (version == 0 ? 4 : 8)))
```

永远为 false（0 不大于 remains），保护被绕过。

随后调用 `SetItemCount(0x20000000)` 尝试分配约 1 GiB vector 空间，
在 64-bit ASAN 构建下引发 `std::bad_alloc`（DoS）。

## PoC 构造

- `saio` box: version=1, flags=0, entry_count=0x20000000，附带 1 个 8 字节假偏移
- 外层结构: ftyp → moov → trak → mdia → minf → stbl → saio
- 所有其他 box（stsd, stts, mdhd, hdlr, tkhd, mvhd）均最小化构造

## 预期结果

- ASAN 构建: `std::bad_alloc` 或 OOM 崩溃，退出码非零
- 非 ASAN 构建: 可能抛出异常或直接崩溃

## 文件列表

| 文件 | 说明 |
|---|---|
| `vuln_003_gen.py` | 生成触发文件 `vuln_003.mp4` |
| `vuln_003_run.sh` | 运行 mp42aac 并收集结果 |
| `vuln_003.mp4` | 生成的 PoC 输入文件 |
| `vuln_003_result.txt` | 程序输出及 ASAN 日志 |
| `vuln_003_status.txt` | 验证状态（VERIFIED_CRASH / UNVERIFIED / ERROR） |
