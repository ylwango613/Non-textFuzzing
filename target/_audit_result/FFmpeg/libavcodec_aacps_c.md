`aacps.c` の残りの部分と関連コードをさらに読み込んで確認します。

## 第1バッチ (行1-600) の分析まとめ

- `hybrid2_re`, `hybrid6_cx`, `hybrid4_8_12_cx`: `in` ポインタが最大 `in[12]` まで参照 → `in[i][44][2]`、i=31 時 in[43] ≤ 44-1 ✓
- `decorrelation` の `memcpy(delay[k], ...)`: delay は `[91][46][2]`、k は NR_BANDS[is34]-1=90 まで、コピー範囲は [14..45] ✓
- `ap_delay` memcpy: `[50][3][37][2]`、アクセス範囲 [32..36] ✓
- `stereo_processing` の H_LUT インデックス `iid_mapped[e][b] + 7 + 23 * iid_quant`: HA/HB は `[46][8][4]`、iid_par は ±(7+8*iid_quant) に検証済みで最大インデックス 45 ✓
- `H11/H12/H21/H22` の `[2][PS_MAX_NUM_ENV+1][PS_MAX_NR_IIDICC]=[2][6][34]`: e+1 の最大は 5 ✓

## 第2バッチ: `ff_ps_apply` と `ff_ps_read_data` の分析

- `top = kx[1]+m[1]+NR_BANDS[is34]-64`: SBR コードで `kx[1]+m[1]<=64` が強制されるため最大 top=91
- `memset(ps->delay+top, 0, (NR_BANDS-top)*...)`: top=91 かつ NR_BANDS=91 のとき 0バイト書き込み ✓
- `num_env` は最大 4（テーブルから）＋フェイクエンベロープ 1 = 5 = PS_MAX_NUM_ENV ✓
- `border_position[PS_MAX_NUM_ENV+1]=[6]`: インデックス 0-5 すべて有効 ✓
- `iid_par/icc_par` の検証ロジック: FFABS <= 7+8*iid_quant と <=7U ✓

## `aacpsdsp_template.c` 分析

- `ps_hybrid_analysis_ileave_c`: i=5-63、`Lbuf[27+63]=Lbuf[90]` < 91 ✓
- `ps_hybrid_synthesis_deint_c`: 同様 ✓
- `ps_decorrelate_c`: `ap_delay[m][n+2-m]` の最大インデックスは m=0,n=31 で 33 < 37 ✓

---

全関数・全バッファアクセス・全検証ロジックを精査した結果、`aacps.c` および関連ファイルには外部から触発可能なメモリ安全性バグは確認されませんでした。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
