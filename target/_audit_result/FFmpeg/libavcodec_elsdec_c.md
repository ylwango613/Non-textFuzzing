境界条件の全数値計算が完了しました。確認された脆弱性を報告します。

---

## VULN: OOB Read in ff_els_decode_bit — Unbounded while-decrement Loop with z=0

- **漏洞类别**: memory-safety
- **函数**: ff_els_decode_bit()
- **行号**: 296–347 (critical: 301, 338, 347)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 8.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted media file (G2Meet/GoToMeeting .g2m video)
- **外部触发路径**: `ffmpeg -i crafted.g2m` → `avcodec_decode_video2()` → `g2m_decode_frame()` → `epic_decode_slice()` → `epic_decode_component_pred()` / `epic_predict_pixel()` → `ff_els_decode_bit()` → OOB read of `els_exp_tab[]`
- **描述**:

  `pAllowable` は `&els_exp_tab[ELS_JOTS_PER_BYTE * 3]`（= `&els_exp_tab[108]`）を指す。`els_exp_tab` のサイズは 145 要素（インデックス 0..144）であり、`pAllowable[i]` の有効域は `i ∈ [-108, 36]`。

  **Step 1 — ctx->j を 0 に誘導**: rung 50（ALps = −72）が使用されると `ctx->j` は 36−72 = −36 となり、2回インポートで 36 に戻った後、`while (pAllowable[ctx->j−1] >= z)` ループが z = 65536 を下回るまで j を逆方向に減らし、**j = 0** で停止する（`pAllowable[−1] = els_exp_tab[107] = 56180 < 65536`）。

  **Step 2 — z = 0 を作る**: 次の呼び出しで rung 170（ALps = −108）を使うと、行 301 の計算は `z = pAllowable[0 + (−108)] = pAllowable[−108] = els_exp_tab[0] = 0`。`els_exp_tab[0..35]` は全てゼロであるため z = 0 が成立する。

  **Step 3 — LPS 分岐で無限ループ**: LPS 分岐（`ctx->t ≤ ctx->x` の場合）において `ctx->t = z = 0`、`ctx->j += −108 = −108`。2回のバイトインポートで j = −36 に戻る。**行 338** の while ループ条件 `pAllowable[ctx->j − 1] >= z`（すなわち `pAllowable[j−1] >= 0`）は、z = 0 かつ `els_exp_tab` の全値が uint32_t（非負）であるため**常に真**となる。ループは j を −37, −38, …, −109 と際限なく減らし、`pAllowable[−110] = els_exp_tab[−2]`（配列先頭より前）を読み出す。下限チェックが一切ない。

  その後、行 347 の `ctx->diff = FFMIN(z - ctx->x, z - pAllowable[ctx->j - 1])` でも同一の OOB 読み取りが発生する。さらに次呼び出し時、行 301 で `pAllowable[deeply_negative_j + ALps]` として追加の OOB 読み取りが連鎖する。

- **触发条件**: 攻撃者が細工した G2Meet（.g2m）動画ファイルを用意し、ELS エントロピー符号化データ中に以下の 2 シンボル列を埋め込む：①rung 50（ALps=−72）を j=36 時に LPS パスで復号させ j=0 に誘導、②rung 170（ALps=−108）を j=0 時に LPS パスで復号させ z=0 の無限ループを起動。入力バイト列を調整して `ctx->x ≥ ctx->t` を満たせば LPS 分岐を強制できる。
- **安全影响**: `els_exp_tab` 配列先頭より前のメモリ（.rodata/.data セクション等）の任意読み取りによる**情報漏洩**、またはマップされていないページを参照した場合の**クラッシュ（DoS）**。読み取り結果が後続の ctx->diff に格納されて算術演算に使用されるため、制御フロー操作の足がかりとなる可能性がある（情報漏洩 + DoS、条件次第で RCE への橋頭堡）。

<!-- AUDIT_PROMPT_VERSION: 1 -->
