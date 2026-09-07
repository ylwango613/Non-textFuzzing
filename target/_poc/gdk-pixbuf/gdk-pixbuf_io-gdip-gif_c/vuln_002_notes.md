# VULN 002 - Technical Notes

## 脆弱性概要

**ID**: VULN 002  
**タイトル**: NULL Pointer Dereference via Unchecked g_try_malloc in GDI+ Property Functions  
**CWE**: CWE-476 (NULL Pointer Dereference)  
**攻撃ベクタ**: crafted GIF/TIFF/JPEG image  

## 脆弱なコード箇所

### 1. `gdip_bitmap_get_frame_delay()` - io-gdip-utils.c:494

```c
if (Ok == GdipGetPropertyItemSize ((GpImage *)bitmap, PropertyTagFrameDelay, &item_size)) {
    PropertyItem *item;
    
    item = (PropertyItem *)g_try_malloc (item_size);  // <-- 戻り値NULL チェックなし
    if (Ok == GdipGetPropertyItem ((GpImage *)bitmap, PropertyTagFrameDelay, item_size, item)) {
        // item が NULL の場合、GdipGetPropertyItem に NULL バッファを渡す -> クラッシュ
        *delay = ((long *)item->value)[...];  // NULL dereference
    }
}
```

### 2. `gdip_bitmap_get_n_loops()` - io-gdip-utils.c:523

```c
if (Ok == GdipGetPropertyItemSize ((GpImage *)bitmap, PropertyTagLoopCount, &item_size)) {
    PropertyItem *item;
    
    item = (PropertyItem *)g_try_malloc (item_size);  // <-- 戻り値NULL チェックなし
    if (Ok == GdipGetPropertyItem ((GpImage *)bitmap, PropertyTagLoopCount, item_size, item)) {
        *loops = *((short *)item->value);  // NULL dereference
    }
}
```

### 3. `gdip_bitmap_get_property_as_string()` - io-gdip-utils.c:411

```c
if (Ok == GdipGetPropertyItemSize ((GpImage *)bitmap, propertyId, &item_size)) {
    PropertyItem *item;
    
    item = (PropertyItem *)g_try_malloc (item_size);  // <-- 戻り値NULL チェックなし
    if (Ok == GdipGetPropertyItem ((GpImage *)bitmap, propertyId, item_size, item)) {
        // item が NULL -> GdipGetPropertyItem に NULL 渡す -> 内部でクラッシュ
    }
}
```

## クラッシュ発生条件

1. GdipGetPropertyItemSize が `item_size = 0` を返す  
   または  
   メモリ不足で `g_try_malloc(item_size)` が NULL を返す

2. NULL チェックなしで `GdipGetPropertyItem(..., NULL)` を呼び出す

3. GdipGetPropertyItem の内部で NULL バッファに書き込もうとしてクラッシュ

## 細工された GIF の構造

```
GIF89a                          # ヘッダー
Logical Screen Descriptor       # 1x1 ピクセル
  Width: 1
  Height: 1
  GCT: 4色
Global Color Table (12 bytes)

Application Extension (Netscape) # ループカウント情報
  NETSCAPE2.0
  Loop Count: 0 (infinite) または 空のサブブロック

Graphics Control Extension       # フレーム遅延
  Delay: 0 centiseconds          # ゼロ遅延でitem_size=0を誘発

Image Descriptor (1x1)
Image Data (最小LZWデータ)

GIF Trailer (0x3B)
```

## PoC ファイル

- `vuln_002.gif` - メインPoC: ゼロ遅延/ゼロループカウント GIF
- `vuln_002_alt.gif` - 代替PoC: 空サブブロックの Netscape Extension

## 修正方法

```c
item = (PropertyItem *)g_try_malloc (item_size);
if (item == NULL) {
    return FALSE;  // または適切なエラー処理
}
if (Ok == GdipGetPropertyItem (..., item)) {
    // ...
}
```

## プラットフォーム制約

**この脆弱性は Windows GDI+ バックエンド専用**

- 脆弱コード: `gdk-pixbuf/io-gdip-utils.c`, `gdk-pixbuf/io-gdip-gif.c`
- これらのファイルは Windows GDI+ ライブラリ (`gdiplus.dll`) に依存する
- Linux ビルドでは GDI+ バックエンドがコンパイルされない
- Linux では代わりに libjpeg/libpng/libtiff 等の ネイティブローダーを使用
- `loaders.cache` にも GDI+ ローダーは存在しない

Linux 上でこの PoC を実行しても、GIF は標準の GIF ローダー（`io-gif.c` 等）で
処理されるため、脆弱なコードパス（`io-gdip-gif.c`）には到達できない。

## 参考

- MSDN: GdipGetPropertyItem - https://docs.microsoft.com/en-us/windows/win32/api/gdiplusheaders/nf-gdiplusheaders-image-getpropertyitem
- PropertyTagFrameDelay: 0x5100
- PropertyTagLoopCount: 0x5101
