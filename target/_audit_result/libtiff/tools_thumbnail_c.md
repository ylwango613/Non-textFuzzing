全関数を詳読し終えた。以下の分析でコードパスを完全に検証した。

---

**グループ A: generateThumbnail() 行 554-577 の精査**

- `rowsize = TIFFScanlineSize(in)` → `tsize_t` (= `int32`) を返す
- `rastersize = sh * rowsize` — `sh` は `uint32`、`rowsize` は `int32`（`tsize_t`）。C 言語の通常算術変換: `int32` は `uint32` に昇格、乗算は 32-bit 符号なし算術。2^32 を超えると切り捨てられ、結果は `tsize_t` (signed) に代入される
- bps=1、spp=1 の制約あり（line 563）。bps=1 では `rowsize = ceil(sw/8)` ≤ 536870912 (内 INT32_MAX 未満)
- **例**: sw=0xFFFFFFF8 → rowsize=536870912。sh=8 → `8 * 536870912 = 4294967296` → uint32 で 0 → `tsize_t` で 0
- `_TIFFmalloc(0)` は Linux で非-NULL を返す。0バイトのバッファ。
- 次に `TIFFReadEncodedStrip(in, s, rp, -1)` が `stripsize = TIFFVStripSize(nrows)` の分だけ書き込む。nrows=3 の場合 stripsize=3*536870912=1610612736 バイトを 0バイトバッファへ書き込み → **ヒープバッファオーバーフロー**

**グループ B: setImage1() 行 522-533 の精査**

- `const uint8* rows[256]` — スタック上の固定 256 要素配列 (インデックス 0..255)
- `nrows = 1`; `rows[0] = ...` (明示代入); while ループ内 `rows[nrows++] = ...`
- nrows=255 → rows[255] に書き込み (valid)、nrows→256
- nrows=256 → rows[256] に書き込み → **スタック OOB**
- `step = rh` (int)、`limit = tnh` (int, default=274)
- rh=70418 のとき dy=0 で while 内 inner-if が正確に 256 回実行される: 70418/274=257, inner-if fires 257-1=256 回

**グループ C: cpStrips()/cpTiles() 行 269-273、303-307**

- `tsize_t *bytecounts;` — 初期化なし
- `TIFFGetField()` の戻り値を確認せず
- STRIPBYTECOUNTS タグが欠如した TIFF ファイルで `bytecounts` はゴミ値のまま
- `bytecounts[s]` → 未初期化ポインタの参照外し

## VULN: Integer Overflow in rastersize Leading to Heap Buffer Overflow
- **漏洞类别**: memory-safety
- **函数**: generateThumbnail()
- **行号**: 566-577
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: thumbnail main() → generateThumbnail() (line 114) → rastersize = sh * rowsize 整数溢出 (line 566) → _TIFFmalloc(0 または小値) 过少分配 (line 568) → TIFFReadEncodedStrip() 写入超出缓冲区 (line 576)
- **描述**: `generateThumbnail()` の line 566 で `rastersize = sh * rowsize` を計算する際、`sh`（uint32、TIFFTAG_IMAGELENGTH）と `rowsize`（tsize_t = int32、TIFFScanlineSize の返値）の積が 32-bit 算術でオーバーフローし、rastersize が 0 または極小の正値になる。bps=1, spp=1 を満たした TIFF（1bpp バイレベル画像）では rowsize = ceil(sw/8)。例えば sw=0xFFFFFFF8 (bps=1) ならば rowsize=536870912、sh=8 のとき 8×536870912=4294967296 → uint32 で 0 → tsize_t で 0。`_TIFFmalloc(0)` はLinux上で非NULLを返す。続く `for (s = 0; s < ns; s++)` ループ内の `TIFFReadEncodedStrip(in, s, rp, -1)` は size=-1 の場合 `TIFFVStripSize(nrows)` に基づく大量バイトを rp（0バイトバッファ）に書き込み、ヒープを破壊する。
- **触发条件**: bps=1, spp=1（1ビット/画素、1サンプル/画素）の TIFF ファイルに IMAGEWIDTH を大きく設定（例: 0xFFFFFFF8）し IMAGELENGTH を small（例: 8）に設定することで、sh×rowsize の 32-bit 乗算オーバーフローを誘発する。STRIPBYTECOUNTS や STRIPOFFSETS も適切に設定する。
- **安全影響**: ヒープ任意書き込みによる攻撃者制御データでのメモリ破壊。理論上リモートコード実行(RCE)まで到達可能。

## VULN: Stack Buffer Overflow via rows[] Array OOB in setImage1
- **漏洞类别**: memory-safety
- **函数**: setImage1()
- **行号**: 523-532
- **CWE**: CWE-121 (Stack-based Buffer Overflow)
- **CVSS v3.1**: 7.8 (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **严重程度**: High
- **攻击向量**: crafted TIFF file
- **外部触发路径**: thumbnail main() → generateThumbnail() (line 114) → setImage() (line 581) → setImage1() (line 544) → while ループ内 rows[nrows++] OOB 書き込み (line 532)
- **描述**: `setImage1()` の line 523 で `const uint8* rows[256]` というスタック上の固定サイズ配列（256 要素、有効インデックス 0〜255）が宣言される。`nrows` は 1 から始まり、Bresenham ステッピングの while ループ（line 528-533）内の条件 `if (err >= limit)` が真になるたびに `rows[nrows++]` への書き込みと nrows インクリメントが行われる。`step = (int)rh`（IMAGELENGTH 値）、`limit = tnh`（デフォルト 274）。dy=0 の最初の外側ループ反復では `err = rh` から始まり、while 内 inner-if は floor(rh/274)-1 回実行される。rh ≥ 70418（= 257×274）のとき inner-if が 256 回実行され、256 回目に `rows[256]` への書き込みが発生しスタックバッファを破壊する。さらに nrows=257 以降も継続し積み重なる。
- **触发条件**: bps=1, spp=1（generateThumbnail の既存チェックを通過するため必要）の TIFF ファイルで IMAGELENGTH（rh）をデフォルト tnh=274 の場合 70418 以上に設定する。rh は INT_MAX (2147483647) 未満でなければならない（超えると step が負になり while は実行されない）。
- **安全影響**: スタック上の rows[] 配列を超えたメモリへの任意ポインタ値書き込みにより、リターンアドレス・フレームポインタ等を破壊し、RCE またはクラッシュ（DoS）を引き起こす可能性がある。

## VULN: Use of Uninitialized Pointer bytecounts in cpStrips
- **漏洞类别**: memory-safety
- **函数**: cpStrips()
- **行号**: 269-273
- **CWE**: CWE-457 (Use of Uninitialized Variable)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: thumbnail main() → cpIFD() (line 116) → cpStrips() (line 337) → TIFFGetField 失败后 bytecounts[s] 未初始化指针解引用 (line 273)
- **描述**: `cpStrips()` の line 269 で `tsize_t *bytecounts;` がスタック上に**未初期化**で宣言される。line 271 の `TIFFGetField(in, TIFFTAG_STRIPBYTECOUNTS, &bytecounts)` の戻り値がチェックされない。TIFFTAG_STRIPBYTECOUNTS タグが存在しない・または取得に失敗した場合、`bytecounts` はスタック上のゴミ値を保持したまま、line 273 の `bytecounts[s]` でそのゴミ値をポインタとして参照外しする。これは未定義動作であり、クラッシュ（セグメンテーション違反）または情報漏洩を引き起こす可能性がある。細工した TIFF ファイルで STRIPBYTECOUNTS タグを欠落させることで再現可能。
- **触发条件**: STRIPBYTECOUNTS タグを持たないか、libtiff の TIFFGetField が 0 を返すように細工された TIFF ファイル（ストリップ構成、TIFFIsTiled が false）。
- **安全影響**: クラッシュ（DoS）、またはスタック上のアドレスが偶然有効なメモリを指す場合はヒープ上のデータの読み書きが発生し得る。

## VULN: Use of Uninitialized Pointer bytecounts in cpTiles
- **漏洞类别**: memory-safety
- **函数**: cpTiles()
- **行号**: 303-307
- **CWE**: CWE-457 (Use of Uninitialized Variable)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted TIFF file
- **外部触发路径**: thumbnail main() → cpIFD() (line 116) → cpTiles() (line 334) → TIFFGetField 失败后 bytecounts[t] 未初始化指针解引用 (line 307)
- **描述**: `cpTiles()` の line 303 で `tsize_t *bytecounts;` がスタック上に**未初期化**で宣言される。line 305 の `TIFFGetField(in, TIFFTAG_TILEBYTECOUNTS, &bytecounts)` の戻り値がチェックされない。TIFFTAG_TILEBYTECOUNTS タグが存在しない・または取得に失敗した場合、`bytecounts` はスタック上のゴミ値を保持したまま、line 307 の `bytecounts[t]` で未初期化ポインタを参照外しする。cpStrips の同一パターン（CWE-457）のタイル画像版。細工した TIFF ファイルで TILEBYTECOUNTS タグを欠落させ、かつ TIFFIsTiled(in) が true を返す構成にすることで再現可能。
- **触发条件**: TILEBYTECOUNTS タグを持たないか TIFFGetField が 0 を返すように細工されたタイル構成 TIFF ファイル（TIFFIsTiled が true を返すものでなければならない）。
- **安全影響**: クラッシュ（DoS）、またはスタック上のゴミポインタが有効なメモリを指す場合は任意メモリ読み書きに発展し得る。

<!-- AUDIT_PROMPT_VERSION: 1 -->
