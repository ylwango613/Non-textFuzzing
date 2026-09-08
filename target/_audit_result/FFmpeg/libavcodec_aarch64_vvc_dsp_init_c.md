全体の分析をまとめます。

**調査結果のまとめ：**

1. **`ff_vvc_dsp_init_aarch64`（行204–436）**：
   - `c->inter.put[2][7][2][2]`へのアクセスはインデックス`[0..1][1..6][0..1][0..1]`——全て境界内
   - `c->inter.dmvr[2][2]`へのアクセスは`[0..1][0..1]`——境界内
   - `c->alf.filter[LUMA=0]`/`[CHROMA=1]`、配列サイズ2——境界内
   - `sao.band_filter`/`sao.edge_filter`は`FF_ARRAY_ELEMS`を使用——安全

2. **`W_AVG_FUN`マクロ（行163–177）**：
   - `shift = denom + FFMAX(3, 15 - bit_depth)`：VVC仕様でdenom∈[0,7]、最大shift=14
   - `offset = (o * (1 << (bit_depth - 8)) + 1) * (1 << (shift - 1))`：
     bd=8でo最大127→offset最大1,048,576、bd=12でo最大2047→offset最大16,769,536。全てint32範囲内、整数オーバーフロー無し
   - `uintptr_t`への左32ビットシフト：aarch64では`uintptr_t`が64ビットなので問題なし

3. **`alf_template.c`インクルード（行121–131）**：
   - ALFフィルタ関数はすべて既知の次元によるループ、バッファ境界は呼び出し元が保証
   - `ALF_ALIGN_BY_4`マクロはwidth≥1の前提があるが、幅0はビットストリームパーサで除外済み
   - `gradient_tmp`は`int32_t[66*66*4]`として確保、`int16_t*`として再利用しても容量は2倍あり安全

4. **アセンブリ関数の前方宣言のみ**：メモリ確保・アクセスなし、単なる関数ポインタ代入ファイル

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
