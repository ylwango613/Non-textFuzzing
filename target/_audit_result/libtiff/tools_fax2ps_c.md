全ての関連コードを読み終わりました。以下にまとめます。

**分析結果サマリー（各グループ別）：**

**グループ1: `main()` - pages 配列と pcompar (行 309–363)**
- `pages` は `uint16*`、各要素は 2 バイト
- `pcompar` は `void*` を `const int*` にキャストして `*pa`（4 バイト）を読む
- `qsort(pages, npages, sizeof(uint16), pcompar)` でソート時、最後の要素 `pages[npages-1]` を比較する際に `pa = (const int*)&pages[npages-1]` → `*pa` は `pages[npages-1]`（2 バイト）＋ アロケーション末尾の 2 バイト外（OOB read）を読む
- **確定的な CWE-125 OOB read**。`-p` オプション使用時に再現可能

**グループ2: `printTIF()` / `TIFFReadEncodedStrip(tif, s, NULL, -1)` (行 261)**
- `buf = NULL` で FAX デコーダを呼び出す
- `Fax3Decode1D` 内で `(*sp->fill)(NULL, ...)` → `printruns` は `(void) buf` で無視 → 安全
- `buf += sp->b.rowbytes` は NULL ポインタ算術（UB）だが、次回以降も `printruns` が buf を無視するため実害なし
- `tif_postdecode` → FAX データには `_TIFFNoPostDecode`（buf 無視）→ 安全

**グループ3: `printruns()` の整数演算 (行 68–154)**
- `x + runlength > lastx` の uint32 overflow: `lastx` が TIFF ファイルから大きな値が来る場合、オーバーフローでキャップが機能しないが、メモリアクセスへの影響なし（PostScript 出力が乱れるのみ）
- `WBarr[l]` アクセス: `l` は最大 9（`WBarr[9].width=1` で必ずサブトラクトが発生し l が 10 に達しない）→ 安全
- `svalue[t]` アクセス: `t` は 6 ビット値（0〜63）、`svalue` は 64 文字 → 安全

**グループ4: `realloc` 戻り値未チェック (行 342–345)**
- OOM で NULL 返却後に即デリファレンス → NULL ptr deref だが、クラフト TIFF ファイルからは到達不可能（コマンドライン引数処理時）

## VULN: pcompar reads 4 bytes from 2-byte uint16 elements causing OOB read
- **漏洞类别**: memory-safety
- **函数**: pcompar()
- **行号**: 309-315, 363
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 3.3 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)
- **严重程度**: Low
- **攻击向量**: command-line -p argument combined with any TIFF file
- **外部触发路径**: fax2ps main() -> getopt('-p') -> realloc pages[] -> qsort(pages, npages, sizeof(uint16), pcompar) -> pcompar() reads *(int*)&pages[npages-1] OOB
- **描述**: `pcompar()` は `qsort` から渡される `void*` を `const int*` にキャストして 4 バイト読む。しかし `pages` 配列の要素サイズは `sizeof(uint16) = 2` バイトであり、`qsort` は隣接する 2 バイト境界のポインタを渡す。最後の要素 `pages[npages-1]` を比較するとき、`pa = (const int*)&pages[npages-1]` で `*pa` が 4 バイト読み出され、アロケーション末尾の 2 バイト外（ヒープアロケータのメタデータ領域）を読み出す OOB read が発生する。`pages` は `malloc(sizeof(uint16))` / `realloc(pages, (npages+1)*sizeof(uint16))` で npages 個の uint16 要素分だけ確保されており、余分なバッファパディングは保証されない。
- **触发条件**: 攻撃者（または悪意あるスクリプト）が `fax2ps -p <N>` のように 1 つ以上の `-p` フラグを指定して任意の TIFF ファイルを渡す。`npages >= 1` の時点で `qsort` が呼ばれ、要素数に関わらず最後の要素の比較で OOB read が発生する。
- **安全影响**: ヒープアロケータのメタデータ（アロケーションサイズ・チャンクフラグなど）を 2 バイト読み取り、ASLR 回避のためのヒープレイアウト情報リークに悪用できる可能性がある（情報開示）。また比較関数が誤った順序を返すことでページ処理順が狂い、意図しない PostScript 出力が生成される。

<!-- AUDIT_PROMPT_VERSION: 1 -->
