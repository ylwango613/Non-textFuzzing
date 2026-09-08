全ファイルを読み終えました。各関数群の分析結果を整理します。

---

**グループ1（readMetadata, lines 135-394）**

- `box.length = 0` → return（安全）
- `box.length = 1` (XLBox未実装) → 残りのswitch処理なしで `io_->seek(position-7, beg)` でループ前方向へのseekが発生。無限ループのリスクはあるが、DataBufへの書き込みは発生しない。
- ColorSpec ICC処理(line 220): `data_length = Safe::add(subBox.length, 8u)` は `subBox.length + 8` だが正しくは `subBox.length - 8`。ただし`DataBuf data(data_length)`は正しくアロケートされており、`iccLength <= data.size() - pad`チェックがコピー境界を保護している。→ 論理バグだが、メモリ安全バグではない。
- ImageHeader: `io_->read(&ihdr, sizeof(ihdr))` = 16バイト読み込み（struct paddingで14+2=16）。2バイトover-readするがihdrはスタック変数でバッファオーバーフローなし。
- UUID/Exif/IPTC/XMP: `enforce(box.length >= 24)` + `rawData.alloc(box.length - 24)` 適切。

**グループ2（printStructure, lines 396-586）**

- subBox処理(line 469): `subBox.length < boxHSize || subBox.length > io_->size() - io_->tell()` 正しくチェック。
- ColorSpec ICC出力(line 511): `enforce(iccLength <= data.size() - pad)` が `out.write(data.c_str(pad), iccLength)` を保護。
- ImageHeader: `enforce(subBox.length == 22)` で正確にチェック。

**グループ3（encodeJp2Header, lines 601-670）**

- `DataBuf output(boxBuf.size() + iccProfile_.size() + 100)`: ICC有り無しどちらも100バイトの余裕で成長分をカバー。算術的に安全（64bit）。
- 各memcpy前に `enforce(newlen <= output.size() - outlen)` がある。ICC有りの場合は `newlen` を実際の書き込みサイズに更新してからenforceするため安全。

**グループ4（doWriteMetadata, lines 672-868）**

- `box.length - 8 <= io_->size() - io_->tell()` チェック（line 733）。
- `DataBuf boxBuf(box.length)` + `io_->readOrThrow(boxBuf.data(8), box.length - 8)` 正当。
- Exif/IPTC/XMP書き込み用の `DataBuf boxData(8 + 16 + rawXxx.size())`: サイズ加算の溢れはないが、`ul2Data(boxDataSize.data(), static_cast<uint32_t>(boxData.size()), bigEndian)` で切り捨てが起きる可能性はある（ただしその場合は壊れた長さフィールドが書かれるだけで、メモリ破壊ではない）。

---

**総合判断**: 全ての DataBuf アロケーション・コピー・インデックスアクセスに適切なガード（enforce, Safe::add, DataBuf::read_uint*/cmpBytes の内部throw）が存在し、外部入力から到達可能なヒープ/スタックオーバーフロー、UAF、整数溢出起因の欠少アロケーションは確認されない。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
