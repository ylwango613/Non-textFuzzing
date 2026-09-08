全コード読み込みが完了しました。最終的な脆弱性分析をまとめます。

## 重要な発見

**`decode_pic()` P フレームパス（cavsdec.c:1126-1130）**:
- `get_ue_golomb` が `AVERROR_INVALIDDATA = -22` を返す（不正な Golomb コード）
- `mb_type = -22 + P_SKIP(1) + skip_mode_flag(0) = -21`
- `if (mb_type > P_8X8)` は**符号付き比較** → `-21 > 5` = FALSE → bounds check を素通り
- `decode_mb_p(h, -21)` 呼び出し → switch misses → `ff_cavs_inter(h, -21)` → `ff_cavs_partition_flags[-21]` **OOB read**

B フレームパスは `if (mb_type <= B_SYM_16X16)` で明示的に負値チェックあり（安全）。P フレームパスにはこのガードが**存在しない**。

---

## VULN: P-frame mb_type signed comparison bypass leads to OOB read in ff_cavs_partition_flags
- **漏洞类别**: memory-safety
- **函数**: decode_pic() → decode_mb_p() → ff_cavs_inter() / ff_cavs_filter()
- **行号**: cavsdec.c:1126-1130 / cavs.c:495
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 5.5 (AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted CAVS media file
- **外部触发路径**: ffmpeg -i crafted.cavs -f null - → avformat_open_input() → avcodec_send_packet() → cavs_decode_frame() → decode_pic() [P-frame branch] → get_ue_golomb() returns AVERROR_INVALIDDATA(-22) → mb_type = -22 + P_SKIP(1) = -21 → signed comparison `mb_type(-21) > P_8X8(5)` is FALSE → decode_mb_p(h, -21) → ff_cavs_inter(h, -21) → ff_cavs_partition_flags[-21] OOB read
- **描述**: `decode_pic()` の P フレームデコードループ（cavsdec.c:1126）において、`get_ue_golomb()` は不正に長い Exp-Golomb 符号を受信した場合に `AVERROR_INVALIDDATA`（-22）を返す。この返り値が `P_SKIP`(+1) と `skip_mode_flag` を加算して `mb_type` に代入されると、符号付き int の -21 になる。その後の境界チェック `if (mb_type > P_8X8)` は**符号付き比較**であるため `-21 > 5` が false となり、不正な mb_type のまま `decode_mb_p(h, -21)` が呼ばれる。`decode_mb_p` 内の switch 文はいずれの case にも一致しないため、そのまま `ff_cavs_inter(h, -21)` および `ff_cavs_filter(h, -21)` が呼ばれる。これらの関数内で `ff_cavs_partition_flags[mb_type]` = `ff_cavs_partition_flags[-21]` が評価され、グローバル配列の開始アドレスから 21 バイト前の `.rodata` 領域が読み出される（OOB Read）。B フレームパスには `if (mb_type <= B_SYM_16X16)` による明示的な負値チェックが存在するが、P フレームパスにはこのガードがなく、脆弱である。
- **触发条件**: 攻撃者はピクチャタイプが P フレームの CAVS ビットストリームを細工し、マクロブロック種別フィールドに 13 個以上の先行ゼロビットを持つ不正な Exp-Golomb 符号（正常な mb_type VLC コードとして解釈不能な系列）を埋め込む。`get_ue_golomb` がこれを `AVERROR_INVALIDDATA`(-22) と判断した時点で本脆弱性が発動する。
- **安全影响**: (1) `ff_cavs_partition_flags` グローバル配列の直前 21 バイトを読み出すことで、`.rodata` セグメント内の隣接データ（パディングや別の定数配列の末尾）が漏洩する可能性がある（情報漏洩）。(2) `ff_cavs_partition_flags` がページ境界付近に配置されている場合、-21 バイトオフセットアクセスが未マップアドレスに当たり SIGSEGV（クラッシュ／DoS）を引き起こす。(3) より重大な別の脆弱性と組み合わせることで ASLR バイパスの補助手段となりうる。直接的な RCE は困難だが、安定した OOB Read として crash-safe な PoC は容易に構成可能。

<!-- AUDIT_PROMPT_VERSION: 1 -->
