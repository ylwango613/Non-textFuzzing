# VULN 001: OOB Heap Read in gdip_bitmap_get_frame_delay via Inflated item_count

## 概要

| 項目 | 内容 |
|------|------|
| ID | VULN 001 |
| タイトル | OOB Heap Read in gdip_bitmap_get_frame_delay via Inflated item_count |
| CWE | CWE-125 (Out-of-bounds Read) |
| ファイル | gdk-pixbuf/io-gdip-utils.c |
| 行番号 | 491-498 |
| 攻撃ベクタ | 細工された GIF アニメーション画像 |

## 脆弱なコードパス

```
gdk_pixbuf__gdip_image_stop_load()   [io-gdip-gif.c]
  └─> stop_load()                    [io-gdip-gif.c]
        └─> gdip_bitmap_get_frame_delay()  [io-gdip-utils.c:481]
```

## 脆弱なコード (io-gdip-utils.c:491-498)

```c
if (Ok == GdipGetPropertyItemSize ((GpImage *)bitmap, PropertyTagFrameDelay, &item_size)) {
    PropertyItem *item;
    item = (PropertyItem *)g_try_malloc (item_size);
    if (Ok == GdipGetPropertyItem ((GpImage *)bitmap, PropertyTagFrameDelay, item_size, item)) {
      item_count = item_size / sizeof(long);   // ← BUG: item_size includes PropertyItem header
      *delay = ((long *)item->value)[(frame < item_count) ? frame : item_count - 1];  // ← OOB read
      success = TRUE;
    }
    g_free (item);
}
```

## 脆弱性の詳細

### 根本原因

`GdipGetPropertyItemSize()` が返す `item_size` は PropertyTagFrameDelay プロパティ
全体のバッファサイズであり、`PropertyItem` 構造体のヘッダ部分を含む:

```
item_size = sizeof(PropertyItem) + num_delays * sizeof(long)
          = [type(2)+id(4)+length(4)+value_ptr(8 or 4)] + N * sizeof(long)
```

しかし脆弱なコードは:

```c
item_count = item_size / sizeof(long);
// = (sizeof(PropertyItem) + N * sizeof(long)) / sizeof(long)
// = sizeof(PropertyItem)/sizeof(long) + N
// = 3 + N  (64-bit: sizeof(PropertyItem)=24, sizeof(long)=8)
// = 4 + N  (32-bit: sizeof(PropertyItem)=16, sizeof(long)=4)
```

つまり実際の遅延エントリ数 N より 3〜4 個多く `item_count` が計算される。

### OOB 読み取りが発生する条件

1. GIF のフレーム数が GCE (Graphic Control Extension) の数より多い
2. GDI+ は GCE のある N フレーム分だけ遅延値を格納する
3. GCE のないフレームに対しても `gdip_bitmap_get_frame_delay(bitmap, frame_idx, &delay)` が呼ばれる
4. `frame_idx >= N` の場合、`frame < item_count` の条件が（item_count が膨らんでいるため）真となり、
   `((long *)item->value)[frame_idx]` が実際の遅延データの外を読む

### メモリレイアウト (例: N=4 遅延値, 64-bit)

```
[Allocated buffer: item_size = 24 + 4*8 = 56 bytes]
0x00: [PropertyItem header: 24 bytes]
         type(2) + id(4) + length(4) + value*(8) + padding(6)
0x18: [delay[0]: 8 bytes]   ← frame 0 の遅延値
0x20: [delay[1]: 8 bytes]   ← frame 1 の遅延値
0x28: [delay[2]: 8 bytes]   ← frame 2 の遅延値
0x30: [delay[3]: 8 bytes]   ← frame 3 の遅延値

item_count = 56 / 8 = 7

frame=5 の読み取り: ((long *)item->value)[5]
  item->value = &buffer[0x18]
  item->value[5] = buffer[0x18 + 5*8] = buffer[0x40]
                 = BEYOND ALLOCATED BUFFER (OOB)
```

## PoC 構造 (vuln_001.gif)

```
GIF89a ヘッダ (1x1 px, 4色 GCT)
NETSCAPE2.0 Application Extension (ループ)
[GCE delay=10] + Image Descriptor + LZW Data  ← frame 0
[GCE delay=20] + Image Descriptor + LZW Data  ← frame 1
[GCE delay=30] + Image Descriptor + LZW Data  ← frame 2
[GCE delay=40] + Image Descriptor + LZW Data  ← frame 3
                 Image Descriptor + LZW Data  ← frame 4 (GCE なし)
                 Image Descriptor + LZW Data  ← frame 5 (GCE なし)
GIF Trailer (0x3B)
```

フレーム 4, 5 は GCE を持たないため GDI+ の PropertyTagFrameDelay には
4エントリしか格納されない。しかし item_count は 7 (=4+3, 64-bit) に膨らむため、
フレーム 5 (index=5) の読み取りで OOB が発生する。

## プラットフォーム制約

この脆弱性は **Windows GDI+ バックエンド専用**。

- ソースファイル `io-gdip-gif.c`, `io-gdip-utils.c` は Windows の GDI+ API
  (`GdipGetPropertyItemSize`, `GdipGetPropertyItem` 等) に依存している。
- Linux ビルドではこれらのファイルはコンパイルされず、GIF のロードには
  別の実装 (`io-gif.c` 等) が使用される。
- `loaders.cache` には "dynamic loading of modules not supported" と記載されており、
  GDI+ ローダは登録されていない。
- `strings` コマンドでも `gdip` の文字列はバイナリに存在しない。

よって Linux 環境では脆弱なコードパスに到達できず、PoC は SKIPPED となる。

## 参考

- PropertyItem 構造体: https://docs.microsoft.com/en-us/windows/win32/api/gdiplusimaging/nl-gdiplusimaging-propertyitem
- PropertyTagFrameDelay: Tag ID 0x5100
- GIF89a 仕様: https://www.w3.org/Graphics/GIF/spec-gif89a.txt
