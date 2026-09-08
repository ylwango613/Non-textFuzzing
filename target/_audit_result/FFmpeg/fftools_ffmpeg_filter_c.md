全ファイル（3605行）を7バッチに分けて精読しました。各セクションの詳細分析結果を記録します。

**バッチ1（0-600行）: `sub2video_copy_rect()`**
- 境界チェック `r->x + r->w > w`（line 318）は符号付き整数オーバーフローの可能性あり。ただしAVSubtitleRectのx/wは最大16ビット（DVB: 12-16bit, PGS: 16bit）であり、65535+65535=131070は32ビットintでオーバーフロー不可。実際の字幕フォーマット経由では再現困難。

**バッチ2（600-1200行）: `read_binary()`, `ofilter_alloc()`**
- `read_binary()`はfsize > INT_MAXチェックあり（line 471）。問題なし。

**バッチ3（1200-1800行）: `fg_create()`, `configure_output_video_filter()`**
- snprintf/av_strlcatfはすべてsizeof引数付きで安全。問題なし。

**バッチ4（1800-2400行）: `ifilter_parameters_from_frame()`**
- line 2376: `memcpy(ifp->displaymatrix, sd->data, sizeof(ifp->displaymatrix))` — sd->sizeチェック欠如。ただしFFmpeg内部コードは常に36バイトで作成するため、クラフトメディアファイルからのトリガーは実質困難。
- line 2391: `memcpy(&ifp->downmixinfo, sd->data, sizeof(ifp->downmixinfo))` — 同上。

**バッチ5-7（2400-3605行）: `send_frame()`, `filter_thread()`, `fg_send_command()`**
- line 3210: `memcmp(sd->data, ifp->displaymatrix, sizeof(ifp->displaymatrix))` — sd->sizeチェック欠如（上記と同一パターン）。
- `fg_send_command()`のav_strdup失敗時のクリーンアップは正確。av_freep(NULL)は安全。
- `fg_finalise_bindings()`のmemmove計算は正確（line 1619-1621）。

**総合判定:**
- `sub2video_copy_rect()`の整数オーバーフローは、標準的な字幕フォーマット（最大16ビット座標）では再現不可能。
- AV_FRAME_DATA_DISPLAYMATRIXのsizeチェック欠如は、FFmpegが常に36バイトで作成するため、通常のクラフトメディアファイルからは外部トリガー不可能。
- フィルタグラフ管理層（本ファイル）は直接のメディアパーサーではなく、下位層（demuxer/decoder）が正常であれば安全に動作する。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
