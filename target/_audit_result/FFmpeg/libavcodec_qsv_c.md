ファイル全体の読み込みが完了しました。関連する補助構造体・関数も確認しました。最終分析を行います。

**グループ 1（lines 1–400）**: コーデックIDマッピング、エラーマッピング、ピクセルフォーマット変換のみ。すべてスイッチ・テーブルルックアップで動的割り当てなし。`ff_qsv_map_frame_to_surface()`のポインタ演算（+1,+2,+3,+6）はピクセルフォーマットの既知ストライド内。**問題なし。**

**グループ 2（lines 408–459）**: `qsv_load_plugins()`。`plugin`の長さを`2 * sizeof(uid.Data) = 32`バイトに検証済み。`snprintf(errorbuf, 128, ...%s..., plugin)`は最大74バイト。**問題なし。**

**グループ 3（lines 754–812）**: `qsv_create_mids()`・`qsv_setup_mids()`。`nb_surfaces`は`frames_hwctx->nb_surfaces`（`int`型）。`av_calloc(nb_surfaces + 2, ...)`で符号付き整数オーバーフローの可能性を確認。`hwcontext_qsv.c:770`で追跡すると`nb_surfaces = ctx->initial_pool_size`、内部フレームパスでは`req->NumFrameSuggested`（`mfxU16`、最大65535）から設定されるため65535+2=65537で安全。`nb_surfaces = -1`の場合は`av_calloc(1, ...)`→`resp->mids[-1]`OOBの経路が存在するが、`nb_surfaces`はハードウェアドライバが設定する値であり、メディアファイルから直接制御不可。

**グループ 4（lines 814–1107）**: `qsv_frame_alloc/free/lock/unlock/get_hdl`は全てハードウェアフレーム管理コード。`qsv_frame_lock()`での`surfaces[0].Info`アクセスはline 937の`nb_surfaces != 0`チェック後だが、`hw_frames_hwctx`は別コンテキストであり理論的に`nb_surfaces=0`の可能性がある。しかし実行パスはハードウェア初期化であり、メディアファイルからの制御経路なし。

**グループ 5（lines 1177–1202）**: `ff_qsv_frame_add_ext_param()`は`QSV_MAX_FRAME_EXT_PARAMS = 4`に対し`num_ext_params < 4`の正しい境界チェックあり。**問題なし。**

**総合判断**: `qsv.c`はIntel QSVハードウェアアクセラレーションの初期化・管理レイヤーであり、メディアファイルの生バイト列を直接パースする処理を含まない。すべての動的割り当てはハードウェアドライバや信頼された内部状態から導出される値を使用している。攻撃者がクラフトされたメディアファイルによって本ファイル内のメモリ安全性バグを外部トリガーできる経路は確認できない。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
