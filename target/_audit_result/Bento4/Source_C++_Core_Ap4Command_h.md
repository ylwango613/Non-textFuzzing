深い解析完了。全ての知見を最終報告にまとめます。

**分析まとめ（グループ1: Ap4Command.cpp / Ap4CommandFactory.cpp）**

- `AP4_CommandFactory::CreateCommandFromStream` のペイロードサイズ（最大 0x0FFFFFFF = 268MB）が上界チェックなし
- `AP4_UnknownCommand` コンストラクタ: `m_Data.SetDataSize(payload_size)` + `stream.Read(…)` の戻り値未検査
- 外部コマンドストリームは `AP4_MemoryByteStream`（OD トラックのサンプルデータ）で包まれているが境界チェックは弱い

**分析まとめ（グループ2: Ap4ObjectDescriptor.cpp, Ap4EsDescriptor.cpp, Ap4DecoderConfigDescriptor.cpp）**

- `AP4_ObjectDescriptor::AP4_ObjectDescriptor()` (line 95–96): `payload_size - AP4_Size(offset - start)` の uint32 アンダーフロー → `AP4_SubStream::m_Size = 0xFFFFFFFE`
- `AP4_EsDescriptor` (line 102–103): 同パターン
- `AP4_DecoderConfigDescriptor` (line 92): `payload_size - 13` のアンダーフロー（定数13）
- `iods` atom → raw file stream が bounded でない → 巨大サブストリームがファイルデータを越えて読み取りを継続

**分析まとめ（グループ3: Ap4ByteStream.cpp）**

- `AP4_SubStream::ReadPartial` の `(AP4_Size)(m_Size - m_Position)` キャスト: m_Size が 0xFFFFFFFF (uint64) でも uint32 にキャストして最大 4GB のリード要求を container に投げる可能性あり

---

## VULN: AP4_ObjectDescriptor substream size integer underflow enables OOB file data parse
- **漏洞类别**: memory-safety
- **函数**: AP4_ObjectDescriptor::AP4_ObjectDescriptor()
- **行号**: 74-103 (Ap4ObjectDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File 解析 → AP4_AtomFactory::CreateAtomFromStream → AP4_IodsAtom::Create(raw_file_stream) → AP4_DescriptorFactory::CreateDescriptorFromStream(raw_file_stream) → AP4_ObjectDescriptor(raw_file_stream, tag, header_size, payload_size=0) → AP4_SubStream(raw_file_stream, offset, 0u - 2u)
- **描述**: `AP4_ObjectDescriptor` コンストラクタはストリームから 2 バイト（ReadUI16）を読み取った後、`payload_size - AP4_Size(offset - start)` でサブストリームサイズを算出する。`payload_size` が 0 や 1（OD 展開サイズエンコーディング由来）のとき `AP4_Size` (uint32_t) 演算でアンダーフローし、`m_Size = 0xFFFFFFFE` ないし `0xFFFFFFFF` の巨大サブストリームが生成される。このサブストリームは `AP4_IodsAtom` 経由で渡される非境界の raw file stream をラップするため、デスクリプタパーサーが `iods` atom 宣言境界を越えてファイル末尾までのデータを逐次デスクリプタとして解析し続ける。誤解釈した `payload_size`（最大 0x0FFFFFFF = 268MB）から `AP4_UnknownDescriptor` が大量確保を試みることで OOM クラッシュに至る。
- **触发条件**: `iods` atom 内に `payload_size = 0` または `payload_size = 1` と宣言した OD デスクリプタ（タグ 0x01 または 0x11）を埋め込んだ MP4 ファイル。URL フラグオフで ReadUI16 後に `offset - start = 2 > payload_size` を成立させる。
- **安全影响**: ヒープ上で最大 268MB の意図外アロケーションが繰り返され DoS（OOM / クラッシュ）。巨大サブストリームが iods 境界を越えてファイルデータを読み取るため後続 atom データの OOB リード（情報漏洩）も派生する。

## VULN: AP4_InitialObjectDescriptor substream size integer underflow enables OOB file data parse
- **漏洞类别**: memory-safety
- **函数**: AP4_InitialObjectDescriptor::AP4_InitialObjectDescriptor()
- **行号**: 215-263 (Ap4ObjectDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File 解析 → AP4_AtomFactory → AP4_IodsAtom::Create(raw_file_stream) → AP4_DescriptorFactory::CreateDescriptorFromStream(raw_file_stream) → tag=0x02/0x10 → AP4_InitialObjectDescriptor(raw_file_stream, header_size, payload_size=1) → ReadUI16 消費 2 バイト → AP4_SubStream(raw_file_stream, offset, 1u - 2u)
- **描述**: `AP4_InitialObjectDescriptor` も同一パターン: ReadUI16(bits) で 2 バイト消費後、URL フラグがオフの場合 5 バイト（OD profile × 5）を追加消費。`payload_size < (offset - start)` のとき `payload_size - AP4_Size(offset - start)` が uint32_t アンダーフローし巨大サブストリームを生成。`AP4_ObjectDescriptor` と同じコードパスでファイル境界越えの OOB リードと DoS が発生する。
- **触发条件**: `iods` atom に IOD タグ（0x02/0x10）で `payload_size <= 6`（URL フラグなし時 ReadUI16+5×ReadUI08 = 7 バイト消費）の IOD デスクリプタを組み込んだ MP4。
- **安全影响**: AP4_ObjectDescriptor と同等: DoS（OOM）および iods 境界を越えたファイルデータの OOB リード。

## VULN: AP4_EsDescriptor substream size integer underflow enables OOB descriptor parse
- **漏洞类别**: memory-safety
- **函数**: AP4_EsDescriptor::AP4_EsDescriptor()
- **行号**: 61-110 (Ap4EsDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File → AP4_StsdAtom 内 esds atom → AP4_EsdsAtom → AP4_DescriptorFactory → AP4_EsDescriptor(substream, header_size, payload_size=2) → ReadUI16 + ReadUI08 で 3 バイト消費 → AP4_SubStream(outer_substream, offset, 2u - 3u = 0xFFFFFFFF)
- **描述**: `AP4_EsDescriptor` コンストラクタは最低でも ReadUI16(m_EsId)(2 バイト) + ReadUI08(bits)(1 バイト) = 3 バイトを固定消費する。`payload_size < 3`（例：payload_size=2）のとき `payload_size - AP4_Size(offset - start) = 2 - 3 = 0xFFFFFFFF`（uint32_t アンダーフロー）となり、`AP4_SubStream::m_Size = 0xFFFFFFFF` の巨大サブストリームが作られる。外側サブストリームが十分大きい場合（OD/iods 経由）、ES デスクリプタ宣言境界を越えたデータが再帰的にデスクリプタとして解析される。
- **触发条件**: esds atom または iods 配下の ES デスクリプタ（タグ 0x03）に `payload_size ≤ 2` を宣言した MP4 ファイル。外側 OD payload_size が十分大きければ越境読み取りが有効。
- **安全影响**: OOB リード（隣接 atom データを誤解析）、誤解釈された大 payload_size による無制限メモリアロケーション DoS。

## VULN: AP4_DecoderConfigDescriptor hardcoded-constant subtraction integer underflow → OOB read
- **漏洞类别**: memory-safety
- **函数**: AP4_DecoderConfigDescriptor::AP4_DecoderConfigDescriptor()
- **行号**: 71-100 (Ap4DecoderConfigDescriptor.cpp)
- **CWE**: CWE-191 (Integer Underflow) → CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → AP4_File → esds atom → AP4_EsdsAtom → CreateDescriptorFromStream → AP4_DecoderConfigDescriptor(stream, header_size, payload_size=12) → 13 バイト固定読み取り後 → AP4_SubStream(stream, start+13, 12u - 13u = 0xFFFFFFFF)
- **描述**: コンストラクタ内で ReadUI08 × 2 + ReadUI24 + ReadUI32 × 2 = 計 13 バイトを固定消費した後、`AP4_SubStream(stream, start+13, payload_size-13)` を生成する。`payload_size < 13` のとき `payload_size - 13` が uint32_t アンダーフローし（例: payload_size=0 → 0xFFFFFFF3）、巨大 `m_Size` を持つサブストリームが生成される。このサブストリームを介してデスクリプタファクトリが宣言境界を越えてデータを読み続け、誤解釈 payload_size からの大アロケーションによる DoS および OOB リードが生じる。
- **触发条件**: esds atom 内の DecoderConfig デスクリプタ（タグ 0x04）に `payload_size ≤ 12` を宣言した MP4 ファイル。
- **安全影响**: 宣言されたデスクリプタ境界を越えたファイルデータの OOB リードと、誤解釈された大 payload_size による無制限ヒープアロケーション DoS（OOM クラッシュ）。

## VULN: AP4_UnknownCommand uncontrolled heap allocation from file-controlled payload_size
- **漏洞类别**: memory-safety
- **函数**: AP4_UnknownCommand::AP4_UnknownCommand()
- **行号**: 58-66 (Ap4Command.cpp), triggered from Ap4CommandFactory.cpp:84
- **CWE**: CWE-789 (Uncontrolled Memory Allocation)
- **CVSS v3.1**: 6.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac input.mp4 → Marlin OD トラック解析 → AP4_CommandFactory::CreateCommandFromStream(AP4_MemoryByteStream) → expandable サイズエンコーディングで payload_size=0x0FFFFFFF (268MB) を読み取り → AP4_UnknownCommand(stream, tag, header_size, 0x0FFFFFFF) → m_Data.SetDataSize(0x0FFFFFFF) → new AP4_Byte[268MB]
- **描述**: `AP4_CommandFactory::CreateCommandFromStream` は MPEG-4 展開サイズエンコーディング（最大 4 バイト、最大値 0x0FFFFFFF = 268,435,455 バイト）から `payload_size` を読み取るが上界チェックを行わない。既知タグ以外のコマンドは `AP4_UnknownCommand` を生成し、コンストラクタ内で `m_Data.SetDataSize(payload_size)` → `new AP4_Byte[payload_size]` を実行する。戻り値検査なし。`stream.Read(m_Data.UseData(), payload_size)` も戻り値未検査のため、実際のサンプルデータが少なくても 268MB のバッファを確保した後に部分読み取りで終了し OOM クラッシュを引き起こす。
- **触发条件**: Marlin OD トラックのサンプルに既知タグ（0x01,0x05）以外のタグバイトと、その後に `0xFF 0xFF 0xFF 0x7F`（4 バイト展開サイズ = 0x0FFFFFFF）を続けた MP4 ファイル。
- **安全影响**: 268MB の非制御ヒープアロケーション → std::bad_alloc または OOM キルによる DoS。`stream.Read` 戻り値未検査のため、バッファの大部分が未初期化のまま使用される可能性（情報漏洩の潜在的リスク）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
