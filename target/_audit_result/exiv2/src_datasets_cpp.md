datasets.cpp の全 601 行と iptc.cpp の全 482 行を読み終えました。

**Batch 1 (datasets.cpp 行 1–300) の分析結果:**
- `envelopeRecord[]` / `application2Record[]` は `constexpr` 静的配列。外部入力なし。
- `records_[]` の要素数は 4（index 0–3）。

**Batch 2 (datasets.cpp 行 300–601) の分析結果:**
- `dataSetIdx(uint16_t number, uint16_t recordId)` — recordId を `envelope(1)` or `application2(2)` に限定後にしか `records_[recordId]` を参照しない。センチネル `0xffff` でループが必ず終端。
- `dataSetIdx(const std::string&, uint16_t)` — 同様の保護。
- `recordId(const std::string&)` — `recordInfo_[i]` アクセスは i が 1 か 2 のときのみ。
- `decomposeKey()` — 入力が不正なら Error を投げる。`std::stoi` の前に `isHex` バリデーション済み。

**iptc.cpp IptcParser::decode の分析結果:**
- ループ条件 `6 <= pEnd - pRead` でバッファ内に常に 6 バイト確保。
- 拡張データセット: `sizeOfSize > 4` チェック + `sizeOfSize > pEnd - pRead` チェック。
- 標準データセット: `sizeData <= pEnd - pRead` 検証後に `readData` 呼出し。
- 拡張サイズ蓄積 `*pRead++ << (8*(sizeOfSize-1))` の UB（符号ビットへのシフト）は後続の境界チェックで無害化される。
- `dataSetIdx` は recordId をファイル由来の値から受け取っても `envelope/application2` 以外は全て -1 を返す。

**結論**: datasets.cpp は静的メタデータとルックアップ関数のみで構成されており、外部入力を直接処理する箇所はない。呼び出し先の iptc.cpp 解析ロジックも適切な境界チェックを実装している。外部から到達可能なメモリ安全性バグは発見されなかった。

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
