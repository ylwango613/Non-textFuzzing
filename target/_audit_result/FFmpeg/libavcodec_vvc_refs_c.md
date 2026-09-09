`refs.c` 全体（700行）を完読し、以下の疑義箇所を順に調査しました：

**調査した疑義箇所まとめ**

1. **`init_slice_rpl`（L508-511）の `rs` 境界チェック欠如**  
   `rs = sh->ctb_addr_in_curr_slice[i]` を `frame->rpl_tab[rs]` のインデックスとして使う際に明示的な範囲チェックがない。しかし `ctb_addr_in_curr_slice` の値は `pps_add_ctus()` で `ctu_rs(rx+x, ry+y)` により計算・格納されており、`*off >= ctb_count` チェックで配列のオフセット自体は守られ、タイル境界の正当な計算から rs 値は `[0, ctb_count-1]` 内に収まる。

2. **`ff_vvc_get_ref_list`（L76-84）の負インデックス**  
   フィルタ（filter.c:630）から `x0 - vertical`/`y0 - !vertical` で呼ばれる際に負になる可能性を調査。境界フラグは `rx > 0` / `ry > 0` 条件付きで設定（ctu.c:2855, 2859）、スライス境界チェックは CTB 境界（pos % ctb_size == 0）でのみ行われるため、実際には x_cb/y_cb が負になる経路は存在しない。

3. **`generate_missing_ref`（L417）の `av_memcpy_backptr` 負 cnt**  
   `cnt = 2*(pps->width >> sps->hshift[i]) - 2`。VVC の最小 CTB サイズが 32 ピクセルで最小有効 width = 32 → クロマ幅 ≥ 16 → cnt ≥ 30 > 0 が保証される。

4. **整数オーバーフロー（pool 割り当て、rpl 割り当て）**  
   `pps->width`/`height` は uint16_t（最大 65535）。`ctb_width * ctb_height` は最大 2048×2048 = 4,194,304、これは int 範囲内。`nb_units * sizeof(RefPicListTab)` は `av_refstruct_allocz` が NULL を返すため OOB にならない。

5. **コロケート参照への OOB アクセス（mvs.c）**  
   `fc->ref->collocated_ref` 設定時に `!is_scaled && ctb_log2_size_y` 一致を要求（refs.c:593-594）、さらに `CHECK_SAMPLES` により解像度一致も強制されるため、CTB 座標は参照フレームの範囲内に収まる。

以上の詳細な追跡の結果、refs.c には外部から craft されたメディアファイルによりトリガー可能なメモリ安全性脆弱性は確認されませんでした。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
