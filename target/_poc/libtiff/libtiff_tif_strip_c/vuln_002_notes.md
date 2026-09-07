# VULN 002 - SKIPPED

## 漏洞概要

- **関数**: `TIFFRasterScanlineSize()` (tif_strip.c:369-371)
- **種別**: PLANARCONFIG_SEPARATE 時に負の tsize_t を返す → heap buffer overflow
- **使用バイナリ**: `tiffsplit`

## SKIPPED 理由

### tiffsplit.c のコードフロー

`tiffsplit.c` の `main()` は次のように動作する:

```
main() → TIFFOpen() → tiffcp() [tiffsplit.c内] → cpStrips() または cpTiles()
```

- `cpStrips()` は `TIFFStripSize()` を使用する
- `cpTiles()` は `TIFFTileSize()` を使用する

**どちらも `TIFFRasterScanlineSize()` を呼び出さない。**

### 報告書の攻撃パスとの不一致

報告書に記載の外部トリガーパス:

```
tiffsplit/tiffcp main() → TIFFOpen() → TIFFReadDirectory() → cpImage() [tiffcp.c:1169]
    → TIFFRasterScanlineSize() [tif_strip.c:369-371]
```

`cpImage()` は `tiffcp.c` に存在する関数であり、`tiffsplit.c` には含まれていない。  
`tiffsplit.c` は独自の `tiffcp()` 関数（ローカル定義）を持つが、これは `cpImage()` を呼び出さない。

### 結論

`tiffsplit` バイナリに TIFF ファイルを渡すだけでは `TIFFRasterScanlineSize()` に到達できない。  
ソースコード変更なしに本脆弱性をトリガーすることは不可能であるため、**SKIPPED** とする。
