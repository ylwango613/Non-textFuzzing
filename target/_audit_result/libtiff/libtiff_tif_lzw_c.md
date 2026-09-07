全ファイルの分析が完了しました。以下に結果をまとめます。

**解析ノート（バッチ1: 行1-325）**
- `LZWSetupDecode`: CSIZE=5120 は定数、malloc 安全。
- `LZWPreDecode` 行268: `tif->tif_rawdata[0]` と `tif->tif_rawdata[1]` を参照する際に `tif->tif_rawcc >= 2` チェックが**ない**。`TIFFFillStrip` で `bytecount=1` は通過する (1 > 0 ✓)。非mmap パスでは `TIFFroundup(1,1024)=1024` バイト確保なのでクラッシュしないが、mmap パスでは `tif_rawdata = tif_base + offset`。strip がファイル末尾なら `rawdata[1]` はマップ範囲外 → SIGBUS。

**解析ノート（バッチ2: 行550-735）**
- `LZWDecodeCompat` 再起動パス (行592-596, 605-608): `LZWDecode` が `&& codep` チェックを持つのに対し、LZWDecodeCompat は持たない。ただし、LZW コードチェーンの不変式（length=N のノードが N ステップで NULL に達する）により、occ>=1 の状況下で NULL に達することは構造的に不可能。コード品質問題であり、外部から確実に利用可能な脆弱性とは判定できないため不報告。
- `LZWDecodeCompat` 行700: 同様。`length=1` ノードで `1 > occ (>=1)` = false でループ終了。NULL に到達しない。

**解析ノート（バッチ3: 行740-1129）**
- `LZWEncode`/`LZWPostEncode`: enc_rawlimit で境界管理。定数 HSIZE=9001 で hash テーブル確保。整数オーバーフロー経路なし。
- `dec_bitsleft = tif_rawcc << 3` (行311): 32 ビット signed long でオーバーフロー可能だが、その場合 dec_bitsleft が負になり即時 CODE_EOI。DoS のみ、メモリ破壊なし。

## VULN: LZWPreDecode OOB Read via 1-Byte LZW Strip at mmap EOF
- **漏洞类别**: memory-safety
- **函数**: LZWPreDecode()
- **行号**: 268
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: tiffsplit main() → TIFFOpen() → TIFFReadEncodedStrip() / TIFFReadScanline() → TIFFFillStrip() → TIFFStartStrip() → LZWPreDecode()
- **描述**: `LZWPreDecode()` の行268において、`tif->tif_rawcc >= 2` の事前チェックなしに `tif->tif_rawdata[0]` と `tif->tif_rawdata[1]` の両バイトを参照する。`TIFFFillStrip()` は `bytecount <= 0` のみを拒否し（行276-282）、`bytecount = 1` は通過する。メモリマップ読み込みパス（`isMapped(tif)` が真かつ fillOrder/NOBITREV 条件を満たす場合）では `tif_rawdata = tif_base + td_stripoffset[strip]` が設定され（行327）、`tif_rawdatasize = 1` となる。Strip がファイル末尾（`stripoffset == file_size - 1`）に配置されている場合、`tif_rawdata[1]` はファイルマップ範囲外のアドレス（`tif_base + file_size`）を参照し、SIGBUS を引き起こす。非 mmap パスでは `TIFFroundup(1, 1024) = 1024` バイトのヒープバッファが確保されるため直接クラッシュしないが、`rawdata[1]` の未初期化（または前ストリップの残留）バイトが旧式デコーダ（`LZWDecodeCompat`）の選択ロジックに影響し、誤ったデコードパスが選択される可能性がある。
- **触发条件**: 攻击者需构造一个 LZW 压缩 TIFF 文件，满足以下条件：(1) `Compression = 5 (LZW)`；(2) 某一 strip 的 `StripByteCount[i] = 1`；(3) 该 strip 数据（单字节）值为 `0x00`（使 `rawdata[0] == 0` 触发第二字节的访问）；(4) `StripOffset[i] = file_size - 1`（strip 位于文件最末一字节），使得 mmap 路径下 `rawdata[1]` 落在映射区域外。
- **安全影响**: 最坏情况下（mmap 路径 + Strip 位于文件末字节），`tif->tif_rawdata[1]` 访问触发 SIGBUS 信号，导致进程崩溃（DoS）。在非 mmap 路径下，读取堆上的陈旧/未初始化字节，使 libtiff 错误地激活向后兼容解码器（`LZWDecodeCompat`），可能导致解码输出异常或后续处理中的行为偏差（信息侧信道）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
