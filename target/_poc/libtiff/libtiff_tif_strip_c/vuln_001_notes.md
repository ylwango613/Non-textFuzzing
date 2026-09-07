# VULN 001 - SKIPPED

## 対象漏洞

- 関数: `TIFFNewScanlineSize()` (tif_strip.c:332-336)
- 漏洞種別: YCbCr raw-arithmetic overflow → heap OOB read in `gtStripContig`
- 外部トリガーパス: RGBA API 経由 → `TIFFRGBAImageGet()` → `TIFFRGBAImageGet_()` → `gtStripContig()` (tif_getimage.c:808)

## SKIPPED 理由

`tiffsplit` はソースコード上で RGBA API を一切使用していない。

### tiffsplit の実際の動作

`tiffsplit.c` の処理フロー:

1. `TIFFOpen()` でファイルを開く
2. `tiffcp()` でメタデータ（タグ）をコピー
3. ストリップ画像の場合: `cpStrips()` → `TIFFReadRawStrip()` / `TIFFWriteRawStrip()` (生データ転送)
4. タイル画像の場合: `cpTiles()` → `TIFFReadRawTile()` / `TIFFWriteRawTile()` (生データ転送)

### 到達不可能な理由

脆弱性トリガーパスは以下の関数呼び出しを必要とする:

```
TIFFRGBAImageGet()
  └→ TIFFRGBAImageGet_()
       └→ gtStripContig()       ← heap OOB read 発生箇所
            └→ TIFFNewScanlineSize()  ← 整数オーバーフロー発生箇所
```

`tiffsplit` はこのうちどの関数も呼び出さない。`TIFFReadRawStrip()` は生のストリップデータをバイト列として読み込むだけで、YCbCr 画像を RGBA に変換する処理（RGBA API）を経由しない。

### 到達可能なバイナリ例

以下のツールであれば RGBA API を経由するため到達可能:
- `tiff2rgba` (`TIFFRGBAImageGet()` を明示的に呼び出す)
- `thumbnail` (`TIFFRGBAImageGet()` を使用)

## 結論

ソースコードの変更なしに `tiffsplit` 経由でこの脆弱性を触発することは不可能。よって **SKIPPED**。
