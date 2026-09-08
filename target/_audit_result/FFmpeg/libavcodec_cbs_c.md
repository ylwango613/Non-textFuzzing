`cbs.c` 全体を分析し終えました。主要な判断ポイントをまとめます。

**バッチ 1（行 1-600）の所見:**
- `cbs_fill_fragment_data`: `av_buffer_alloc(size + AV_INPUT_BUFFER_PADDING_SIZE)` — `size` は `int` 由来のため `SIZE_MAX` 近傍には到達不能。`av_malloc` は `max_alloc_size (INT_MAX)` チェックあり → 安全。
- `cbs_alloc_unit_data`: 同構造で安全。
- `cbs_read_data` → `split_fragment` / `read_unit`: 実解析はコーデック固有ファイルへ委譲。

**バッチ 2（行 600-1069）の所見:**
- `cbs_insert_unit`（行 747）: `av_malloc_array(frag->nb_units*2 + 1, sizeof(*units))` — `nb_units` は `int` で、`*2` が signed overflow を引き起こす理論的 UB があるが、`av_malloc_array` 内部の `size_mult` + `av_malloc` の `max_alloc_size` チェックにより NULL が返り、直後の `if (!units)` で捕捉される。10億ユニット相当の入力が必要で現実的でない。
- 行 751: `nb_units_allocated = 2*nb_units_allocated + 1` は割り当てサイズ `nb_units*2+1` と一致（不変条件: 両者は等しい状態でこのブランチに入る）。
- `cbs_clone_noncomplex_unit_content`（行 944）: `memcpy(copy, src, desc->content_size)` — コンパイル時定数 → 安全。
- `trace_read_log` の `name[j++] = str[i++]`（行 526）: 境界チェックなしだが、`str` はコーデックのソース中のコンパイル時文字列リテラルであり外部入力で制御不能。また `ctx->trace_enable = 0` がデフォルトで有効化不可。

**外部ライブラリ確認:**
- `av_malloc_array` → `size_mult` で乗算オーバーフロー保護あり。
- `av_buffer_alloc` → `av_malloc` → `max_alloc_size = INT_MAX` チェックあり。

結論として、`cbs.c` のメモリ安全性は堅牢であり、クラフトされたメディアファイルで外部から到達可能・悪用可能なメモリ安全バグは確認されませんでした。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
