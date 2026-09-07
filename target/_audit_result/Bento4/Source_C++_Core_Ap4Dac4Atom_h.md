Now I have enough context to analyze the vulnerabilities. Let me trace the bit-reading sequence carefully:

**Tracing bits read in `ac4_dsi_version == 1` branch (minimal path, `bitstream_version <= 1`):**
- Line 77: `ReadBits(3)` → triggers `ReadCache()` at pos=0, m_Position→4, m_BitsCached=29
- Line 87: `ReadBits(7)` → m_BitsCached=22
- Line 88: `ReadBits(1)` → m_BitsCached=21
- Line 89: `ReadBits(4)` → m_BitsCached=17
- Line 90: `ReadBits(9)` → m_BitsCached=8
- *(assume `bitstream_version<=1`, skip UUID block)*
- Line 101: `ReadBits(2)` → m_BitsCached=6
- Line 102: `ReadBits(32)` → triggers `ReadCache()` at pos=4, m_Position→8, m_BitsCached=6
- Line 103: `ReadBits(32)` → triggers `ReadCache()` at pos=8, m_Position→12, m_BitsCached=6
- Line 106–108: `GetBitsRead()` = 8×12−6 = 90; 90%8=2 → `SkipBits(6)` → m_BitsCached=0
- **Total consumed: m_Position=12, m_BitsCached=0**

With `payload_size=11`, the BitReader constructor pads to 12 bytes (`ceil(11/4)*4`).

When parsing the first presentation (n_presentations > 0), Line 117: `ReadBits(8)` for `presentation_version` → `m_BitsCached==0`, calls `ReadCache()` at **m_Position=12**, reading bytes `[12..15]` — **4 bytes beyond the 12-byte allocated buffer** (heap OOB read).

The `ReadCache()` function (Ap4Utils.cpp:430) is:
```cpp
const AP4_UI08* out_ptr = m_Buffer.GetData()+m_Position;
return (((BitsWord) out_ptr[0]) << 24) | ... | out_ptr[3];
```
No bounds check whatsoever.

Additionally, the `pres_bytes` extended field (lines 119-121) allows attacker to set `pres_bytes = 255 + 65535 = 65790`, causing the skip loop (lines 173-175) to call `SkipBits(8)` up to 65790 times, each potentially advancing `m_Position` far beyond the buffer.

## VULN: Heap OOB Read via Unbounded AP4_BitReader in AC4 DSI Presentation Parsing
- **漏洞类别**: memory-safety
- **函数**: AP4_Dac4Atom::AP4_Dac4Atom() / AP4_BitReader::ReadCache()
- **行号**: 76-176 (Ap4Dac4Atom.cpp), 430-434 (Ap4Utils.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File::AP4_File() → AP4_AtomFactory::CreateAtomFromStream() → AP4_Dac4Atom::Create(size_32, stream) [Ap4AtomFactory.cpp:724] → AP4_Dac4Atom::AP4_Dac4Atom(size, payload) [Ap4Dac4Atom.cpp:62] → AP4_BitReader bits(payload, payload_size) [line 76] → presentation parsing loop [line 113] → bits.ReadBits(8) [line 117] → AP4_BitReader::ReadBits() → AP4_BitReader::ReadCache() [Ap4Utils.cpp:430] reads 4 bytes at m_Buffer.GetData()+m_Position where m_Position == m_Buffer.GetBufferSize()
- **描述**: `AP4_BitReader::ReadCache()` は境界チェックなしで `m_Buffer.GetData()+m_Position` から4バイトを読み取る。AC4 DSI v1（`ac4_dsi_version==1`）の解析中、ヘッダフィールド（3+7+1+4+9+2+32+32=90 ビット）を読み取った後、`payload_size=11` のとき BitReader バッファは12バイト（4バイト境界にパディング）しか持たないが `m_Position=12`（バッファの末尾）となる。`n_presentations>0` の場合、`ReadBits(8)` がさらに `ReadCache()` を呼び出し、`m_Position=12`（12バイトバッファの範囲外）から4バイトをヒープ外読み取りする。さらに攻撃者が `pres_bytes=65790`（255+65535）を設定すると、skip ループ（lines 173-175）が `SkipBits(8)` を最大65787回呼び出し、ヒープの大幅な外部領域を読み取る。
- **触発条件**: MP4 ファイル内に `ac_-4`（または `enca`）サンプルエントリを含む `moov/trak/mdia/minf/stbl/stsd` ボックスを配置し、その中の `dac4` ボックスペイロードを次のように構成する: (1) `ac4_dsi_version=1`（3ビット=0b001）; (2) `bitstream_version<=1`（7ビット）でUUID節をスキップ; (3) `n_presentations=511`（9ビット最大値）; (4) ペイロード合計11バイト（サニティチェック `payload_size<11` を通過する最小値）。
- **安全影響**: ヒープ上の隣接メモリの読み取りによる情報漏洩（スタックアドレス・ヒープメタデータ・隣接オブジェクト内容の漏洩）、および未マップメモリへのアクセスによるプロセスクラッシュ（DoS）。メモリレイアウトによっては、ヒープポインタ漏洩を足がかりにした後続の RCE エクスプロイト連鎖も潜在的に可能。

<!-- AUDIT_PROMPT_VERSION: 1 -->
