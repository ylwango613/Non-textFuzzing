`ffjni.c` の全 413 行を読み込み、以下の観点で詳細に分析しました：

**分析結果まとめ**

| 関数 | 確認内容 | 判定 |
|------|----------|------|
| `ff_jni_get_env` | JVM アタッチ/デタッチのみ、ユーザー制御サイズなし | 問題なし |
| `ff_jni_jstring_to_utf_chars` | `av_strdup(utf_chars)` — JVM 管理の文字列、媒体ファイル由来でない | 問題なし |
| `ff_jni_exception_get_summary` | `string` が非 NULL のまま `goto done` → L241 の `DeleteLocalRef(string)` | JNI spec 上、例外発生後の戻り値は undefined だが、DeleteLocalRef(NULL) は safe；JVM crash 可能性があるも攻撃者制御不可 |
| `ff_jni_init_jfields` | `jfields + offset` への書き込み — offset はコンパイル時定数テーブル由来 | 攻撃者制御不可 |
| `ff_jni_reset_jfields` | 同上 | 問題なし |

**重要な観察：**
- このファイルは Android MediaCodec（ハードウェアデコーダ）向け JNI グルーコードであり、クラフトされたメディアファイルから直接トリガーされるコードパスは存在しない
- `av_malloc`/`memcpy` は一切使用されず、ユーザー制御サイズの算術演算もない
- `ff_jni_init_jfields` の `offset` フィールドはすべてコンパイル時定数（`jfields_mapping` テーブル）から来ており、メディアファイルフィールドではない
- JNI 経由でのメモリ破壊は JVM サンドボックスにより制限される

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
