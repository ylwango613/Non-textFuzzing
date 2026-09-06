#!/bin/bash
# FFmpeg 全量安全审计脚本（libavformat/ libavcodec/ libavutil/ fftools/ 生产代码，仅内存安全漏洞）
#
# 用法:
#   ./ffmpeg_audit.sh                        # 默认 resume 模式（审计 + PoC 生成）
#   ./ffmpeg_audit.sh --restart              # 清除结果，从头开始
#   ./ffmpeg_audit.sh --restart-from 50      # 从第50个文件开始
#   ./ffmpeg_audit.sh --list-pending         # 仅列出未审计文件
#   ./ffmpeg_audit.sh --stats                # 统计已有审计结果
#   ./ffmpeg_audit.sh --no-poc               # 只审计，跳过 PoC 生成
#   ./ffmpeg_audit.sh --poc-only             # 只跑 PoC 生成阶段（跳过审计）
#   ./ffmpeg_audit.sh --restart-poc          # 清除已有 PoC，重新生成
#   ./ffmpeg_audit.sh libavformat/mov.c      # 审计指定文件

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

SOURCE_DIR="/data/ylwang/non-textfuzz/target/FFmpeg"
OUTDIR="$SOURCE_DIR/FFmpeg"
LOGFILE="$OUTDIR/ffmpeg_audit.log"
mkdir -p "$OUTDIR"

PROMPT_VERSION="1"
VERSION_MARKER="AUDIT_PROMPT_VERSION"

# ============================================================
# 选项解析
# ============================================================
MODE="resume"
RESTART_FROM=0
RUN_AUDIT=1
RUN_POC=1
RESTART_POC=0
POSITIONAL=()

while [[ $# -gt 0 ]]; do
    case $1 in
        --resume)       MODE="resume";        shift ;;
        --restart)      MODE="restart";       shift ;;
        --restart-from)
            MODE="restart-from"
            RESTART_FROM="$2"
            shift 2
            ;;
        --list-pending) MODE="list-pending";  shift ;;
        --stats)        MODE="stats";         shift ;;
        --no-poc)       RUN_POC=0;            shift ;;
        --poc-only)     RUN_AUDIT=0;          shift ;;
        --restart-poc)  RESTART_POC=1;        shift ;;
        -h|--help)
            sed -n '2,17p' "$0"
            exit 0
            ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

# ============================================================
# 文件名 -> 结果路径的映射
# ============================================================
tag_for() {
    local f="$1"
    local name dir
    name=$(basename "$f")
    name="${name//./_}"
    dir=$(dirname "$f" | tr '/' '_')
    echo "${dir}_${name}"
}

result_is_current() {
    local result="$1"
    [ -f "$result" ] || return 1
    grep -q "^<!-- ${VERSION_MARKER}: ${PROMPT_VERSION} -->$" "$result" 2>/dev/null
}

# ============================================================
# 构建文件列表
# ============================================================
if [ $# -gt 0 ]; then
    FILES=("$@")
else
    SCAN_ROOTS=(
        "$SOURCE_DIR/libavformat"
        "$SOURCE_DIR/libavcodec"
        "$SOURCE_DIR/libavutil"
        "$SOURCE_DIR/fftools"
    )

    ROOT_ERR=0
    for root in "${SCAN_ROOTS[@]}"; do
        if [ ! -d "$root" ]; then
            echo "FATAL: scan root missing: $root" >&2
            ROOT_ERR=1
        elif [ -z "$(find "$root" -name '*.c' -print -quit)" ]; then
            echo "FATAL: scan root has no .c files: $root" >&2
            ROOT_ERR=1
        fi
    done
    if [ "$ROOT_ERR" = "1" ]; then
        echo "Aborting: one or more scan roots are missing/empty." >&2
        exit 2
    fi

    mapfile -t FILES < <(
        find \
            "${SCAN_ROOTS[@]}" \
            -name '*.c' \
            ! -path '*test*' \
            ! -path '*fuzzing*' \
            ! -path '*compat*' \
            | sed "s|^$SOURCE_DIR/||" | sort
    )
fi

VALID_FILES=()
MISSING=0
for f in "${FILES[@]}"; do
    if [ -f "$SOURCE_DIR/$f" ]; then
        VALID_FILES+=("$f")
    else
        echo "WARNING: File not found, skipping: $f"
        MISSING=$((MISSING + 1))
    fi
done
FILES=("${VALID_FILES[@]}")
TOTAL=${#FILES[@]}

# ============================================================
# --stats 模式
# ============================================================
if [ "$MODE" = "stats" ]; then
    mkdir -p "$OUTDIR/poc"
    done_count=$(find "$OUTDIR" -maxdepth 1 -name '*.md' 2>/dev/null | wc -l | tr -d ' \n')
    vuln_files=$({ grep -rl --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | { grep -v '/poc/' || true; } | wc -l | tr -d ' \n')
    vuln_entries=$({ grep -rh --include='*.md' "^## VULN:" "$OUTDIR"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_files=$(find "$OUTDIR/poc" -name '.done' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$OUTDIR/poc"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_total=$(find "$OUTDIR/poc" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    echo "=========================================="
    echo " FFmpeg Audit Statistics"
    echo " Total production files:  $TOTAL"
    echo " Files audited:           $done_count"
    echo " Files remaining:         $((TOTAL - done_count))"
    echo " Files with vulns:        $vuln_files"
    echo " Total vuln entries:      $vuln_entries"
    echo " Files with PoCs done:    $poc_files"
    echo " PoCs total / verified:   $poc_total / $poc_verified"
    echo "=========================================="
    exit 0
fi

# ============================================================
# --list-pending 模式
# ============================================================
if [ "$MODE" = "list-pending" ]; then
    PENDING=()
    STALE=0
    for f in "${FILES[@]}"; do
        tag=$(tag_for "$f")
        result="$OUTDIR/${tag}.md"
        if ! result_is_current "$result"; then
            PENDING+=("$f")
            [ -f "$result" ] && STALE=$((STALE + 1))
        fi
    done
    echo "=========================================="
    echo " Pending files: ${#PENDING[@]} / $TOTAL  (含 $STALE 个 prompt-v$PROMPT_VERSION 过期需重审)"
    echo "=========================================="
    for f in "${PENDING[@]}"; do
        echo "  $f"
    done
    exit 0
fi

# ============================================================
# --restart / --restart-from
# ============================================================
if [ "$MODE" = "restart" ]; then
    echo "MODE: restart — clearing ALL previous results..."
    rm -f "$OUTDIR"/*.md
fi

if [ "$MODE" = "restart-from" ]; then
    echo "MODE: restart-from $RESTART_FROM — clearing results from file #$RESTART_FROM onwards..."
    idx=0
    for f in "${FILES[@]}"; do
        idx=$((idx + 1))
        if [ "$idx" -ge "$RESTART_FROM" ]; then
            tag=$(tag_for "$f")
            rm -f "$OUTDIR/${tag}.md"
        fi
    done
fi

# ============================================================
# 审计 prompt 模板
# ============================================================
AUDIT_PROMPT_TEMPLATE='你是一个顶级 C 安全审计专家，正在对 FFmpeg（C 多媒体框架）进行授权安全审计，目标是发现可提交 bug bounty 的真实内存安全漏洞。

请仔细阅读文件 __SOURCE_DIR__/__FILE__ 的完整内容。
同时用 Grep/Glob/Read 查看相关的头文件、宏定义、调用的函数实现，以理解完整上下文。

**大文件必须多遍 / 分组深读——"一遍读完就判 clean"是历史漏报根因：**
- 若文件较大（≳800 行），不要一遍扫完就下结论。按函数群拆分，**并行派发多个 subagent**
  （一条消息内同时发出 N 个 Agent 调用，subagent_type=general-purpose），
  每个 subagent 深读一个函数群并各自独立找漏洞；你再把它们的发现【全部重新整理】成 `## VULN:` 块。
- 每个函数群都要追到边界条件（malloc/av_malloc 大小、数组索引、整数溢出、
  chunk/atom/packet size 与 buffer size 的比较）。

项目背景：
- FFmpeg 是一个 C 多媒体框架，包含：
  - **Demuxers**（libavformat/）：解析容器格式，如 mp4/mov、mkv/webm、avi、flv、mp3、ogg 等。
  - **Decoders**（libavcodec/）：解码压缩视频/音频帧（H.264、HEVC、AAC、MP3、FLAC 等）。
  - **Utilities**（libavutil/）：内存管理、数学、像素格式等基础设施。
  - **Tools**（fftools/）：ffmpeg.c 主工具入口。
- 主要入口：命令行 `ffmpeg -i <file> -f null -`，直接解析攻击者控制的媒体文件。
- 代码库非常庞大，优先关注：movenc.c、mov.c、matroskadec.c、flacdec.c、
  h264dec.c、hevcdec.c、aac*.c、mp3*.c。

**本次审计范围：仅内存安全漏洞**（memory-safety bugs only）。

重点漏洞模式——请主动用 Grep 在当前文件及调用链中搜索：

1. **整数溢出导致 av_malloc 欠分配**：nb_samples * sample_size 或
   nb_channels * sample_rate 在 av_malloc 前无溢出检查 → heap underalloc → OOB write。
2. **Codec extradata 堆溢出**：avcodec_parameters_copy 拷贝 extradata_size 字节，
   但 size 来自不可信容器且未校验 → heap overflow。
3. **Seek table/index 欠分配**：从文件读取 nb_entries → malloc(nb_entries * sizeof(entry))
   无溢出检查 → heap underalloc → OOB write。
4. **Packet data OOB**：av_packet_from_data 使用用户控制的 size →
   decoder 内 OOB read/write。
5. **Demuxer 边界：chunk/atom size 堆溢出**：从 atom/tag 头读取 chunk_size，
   直接用作 memcpy/read 长度未与 buffer size 对比 → heap overflow。
6. **固定大小栈缓冲区溢出**：codec name / metadata tag 拷贝到固定大小栈缓冲区 → stack overflow。
7. **AVFrame 像素格式整数溢出**：从容器读取 width/height 用于 av_image_alloc 无校验 →
   整数溢出 → underalloc → OOB。

不报告以下情形：
- 仅在非默认编译选项下才能触发的问题。
- 纯假设性漏洞或已知 CVE 的重复。
- 仅造成 assert 失败但无内存破坏暗示的 DoS。

主动使用工具获取上下文（必须执行以下步骤，不能跳过）：
1. 用 Grep 搜索该文件中关键函数的调用点。
2. 对处理外部输入的函数，追踪数据来源：是从容器字节流读取的字段？
3. 对 av_malloc/av_realloc/memcpy 调用，确认调用处是否有大小校验。
4. 用 Grep 搜索关键宏/常量定义（如 INT_MAX、AV_CODEC_CAP_*、AVPROBE_SCORE_MAX 等）。
5. 关注 chunk_size / nb_entries / extradata_size 等来自文件的字段是否有上界校验。

==================== 最终输出契约（极其重要，违反则结果作废）====================
你这次任务的【最终回复，也就是最后一条消息】会被原样保存为审计报告，并被自动化脚本用 grep "^## VULN:" 解析来决定是否生成 PoC。因此必须严格遵守：
1. 每一个漏洞都必须是独立的块，以 `## VULN:` 开头（必须行首顶格，前面不能有任何字符），严格按下面"输出格式"逐字段输出。
2. 严禁用表格、散文段落或要点列表来"汇总"漏洞；严禁出现"Final Summary""综上"之类的过渡话术。最终消息里除了若干 `## VULN:` 块（或单独的 NO_VULN_FOUND）之外，不要有任何其它内容。
3. 即使你使用了 subagent 协助分析，也必须把它们报告的每一个漏洞【全部重新整理】成完整的 `## VULN:` 块，在你自己的最终消息里逐条完整输出。
4. 没有发现任何可被外部触发的漏洞时，最终消息【只输出一行】：NO_VULN_FOUND
==================================================================================

输出格式（每个漏洞一个块）：
## VULN: <简短英文标题>
- **漏洞类别**: memory-safety
- **函数**: xxx()
- **行号**: xxx-xxx
- **CWE**: CWE-XXX (名称)
- **CVSS v3.1**: X.X (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H 等，根据攻击向量选择)
- **严重程度**: Critical/High/Medium/Low
- **攻击向量**: crafted media file
- **外部触发路径**: <从入口到漏洞点的完整调用链，例如: ffmpeg -i <file> -f null - -> avformat_open_input() -> ... -> vulnerable_func()>
- **描述**: xxx（说明漏洞成因——内存破坏机制）
- **触发条件**: xxx（攻击者需要构造怎样的畸形媒体文件，如 mp4/mkv/avi/flv）
- **安全影响**: xxx（最坏情况下的利用后果：RCE/信息泄露/DoS/…）'

# ============================================================
# PoC 生成相关设置
# ============================================================
BIN="$SOURCE_DIR/build_test/ffmpeg"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/FFmpeg"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=1
if [ "$RUN_POC" = "0" ]; then
    POC_ENABLED=0
elif [ ! -x "$BIN" ]; then
    echo "WARNING: $BIN not executable — PoC phase will be skipped."
    echo "         Build FFmpeg first with ASAN:"
    echo "           ./configure --prefix=\$PWD/build_test --enable-asan \\"
    echo "             --extra-cflags='-fsanitize=address -g -O1' \\"
    echo "             --extra-ldflags='-fsanitize=address'"
    echo "           make -j\$(nproc) && make install"
    echo "         Then rerun with --poc-only."
    POC_ENABLED=0
fi

if [ "$POC_ENABLED" = "1" ]; then
    mkdir -p "$POC_BASE"
    if [ "$RESTART_POC" = "1" ]; then
        echo "MODE: --restart-poc — clearing all existing PoCs..."
        rm -rf "$POC_BASE"
        mkdir -p "$POC_BASE"
    fi
fi

POC_PROMPT_TEMPLATE='你是 FFmpeg 安全研究员。基于已有的漏洞审计报告，为每个漏洞生成可实际复现的 PoC。

==================== 硬性规则（违反则 PoC 无效）====================
本项目的 __SOURCE_DIR__/build_test/ffmpeg 已经是 ASAN 构建。
所有 PoC 必须通过这个真实二进制触发。

1. **禁止自写 harness**：绝对不允许把漏洞函数抠出来单独编译，也不允许链接 FFmpeg 内部头文件写 C 程序。
2. **内存漏洞的唯一合法验证途径**：
   - 用 Python 生成一个精心构造的最小畸形媒体容器文件（如 mp4 atoms/mkv EBML/avi RIFF，
     含有恶意大小字段），然后直接用 ffmpeg 命令行处理该文件，让 ASAN 在真实执行路径中自行报错。
3. 唯一可接受的辅助程序是：
   - 用 Python 生成畸形输入文件的脚本（vuln_NNN_gen.py），只用二进制方式构造容器字节。
   - 运行 ffmpeg 二进制并收集 ASAN 输出的 shell 脚本（vuln_NNN_run.sh）。
====================================================================

漏洞报告:   __RESULT_FILE__
源代码文件: __SOURCE_DIR__/__SOURCE_FILE__
PoC 目录:   __POC_DIR__
二进制路径: __SOURCE_DIR__/build_test/ffmpeg

==================== PoC 生成范围限制（必须严格执行）====================
下列情况**跳过 PoC，直接写 vuln_NNN_status.txt 第一行为 SKIPPED**，不生成任何运行脚本：
- 漏洞无法通过向 ffmpeg 命令行传递一个畸形媒体文件来触发。
对于 SKIPPED 的漏洞：在 vuln_NNN_notes.md 里写明跳过原因，不生成 _run.sh 和 _result.txt。
======================================================================

步骤：
1. Read 漏洞报告，列出全部以 "## VULN:" 开头的漏洞条目，按出现顺序编号 1,2,3,...
2. **对每个漏洞并行派发一个 subagent**（一条消息内同时发出 N 个 Agent 调用，subagent_type=general-purpose）。
   每个 subagent 严格只负责自己那一个 VULN。

每个 subagent 必须完成：
A. 读懂对应 VULN 的函数/行号/触发条件/攻击向量，必要时 Read 源码与相关头文件。
   **首先判断是否命中上述 SKIPPED 条件**，命中则直接写 SKIPPED 状态并退出。
B. 在 __POC_DIR__/ 下生成（NNN 为 3 位零填编号）：
   - vuln_NNN_gen.py  —— Python 脚本，生成最小畸形容器文件 vuln_NNN_input.<ext>
     （如 .mp4/.mkv/.avi/.flv；只用二进制方式构造 atoms/EBML/RIFF 字节，不调用 FFmpeg API）
   - vuln_NNN_run.sh  —— 可执行 shell，流程：
       #!/bin/bash
       set -euo pipefail
       cd "$(dirname "$0")"
       BIN=__SOURCE_DIR__/build_test/ffmpeg
       python3 vuln_NNN_gen.py
       ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
         "$BIN" -i vuln_NNN_input.<ext> -f null - > vuln_NNN_result.txt 2>&1 || true
       cat asan.log.* >> vuln_NNN_result.txt 2>/dev/null || true
   - vuln_NNN_notes.md  —— 简短说明 PoC 思路、触发路径、预期现象
C. chmod +x vuln_NNN_run.sh，然后**实际运行它**：
       timeout 60 bash __POC_DIR__/vuln_NNN_run.sh > __POC_DIR__/vuln_NNN_result.txt 2>&1
       echo "EXIT=$?" >> __POC_DIR__/vuln_NNN_result.txt
   验证通道：
   - 内存破坏类：ASAN "heap-buffer-overflow"、"stack-buffer-overflow"、
     "heap-use-after-free" 等
D. 根据 vuln_NNN_result.txt 判定，写 __POC_DIR__/vuln_NNN_status.txt：
   第一行必须是：
     VERIFIED_CRASH     —— ASAN 在真实 ffmpeg 执行路径中报错
     VERIFIED_BEHAVIOR  —— 无崩溃但有明确异常行为
     UNVERIFIED         —— 跑通但无漏洞迹象
     ERROR              —— PoC 生成或运行本身报错
E. 不要修改 __POC_DIR__ 以外的任何文件，不要修改源码。

全部 subagent 跑完后，主代理输出一行汇总：每个 VULN 编号 + 状态。

工具白名单：Read, Write, Bash, Grep, Glob, Agent。'

POC_PIDS=()
POC_LAUNCHED=0
POC_SKIPPED=0
AUDIT_PIDS=()

poc_reap() {
    local alive=() pid
    for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}"; do
        if kill -0 "$pid" 2>/dev/null; then
            alive+=("$pid")
        fi
    done
    POC_PIDS=("${alive[@]+"${alive[@]}"}")
}

poc_throttle() {
    while :; do
        poc_reap
        [ "${#POC_PIDS[@]}" -lt "$POC_PARALLEL" ] && break
        sleep 3
    done
}

audit_reap() {
    local alive=() pid
    for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
        if kill -0 "$pid" 2>/dev/null; then
            alive+=("$pid")
        fi
    done
    AUDIT_PIDS=("${alive[@]+"${alive[@]}"}")
}

audit_throttle() {
    while :; do
        drain_events
        audit_reap
        [ "${#AUDIT_PIDS[@]}" -lt "$AUDIT_PARALLEL" ] && break
        sleep 2
    done
}

jobs_cleanup() {
    local pid
    for pid in "${POC_PIDS[@]+"${POC_PIDS[@]}"}" "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
        if kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
    done
}
trap jobs_cleanup EXIT INT TERM

launch_poc_bg() {
    local f="$1" tag="$2" result="$3" vuln_n="$4"
    [ "$POC_ENABLED" = "1" ] || return 0

    local POC_DIR="$POC_BASE/$tag"
    if [ -f "$POC_DIR/.done" ]; then
        POC_SKIPPED=$((POC_SKIPPED + 1))
        return 0
    fi
    mkdir -p "$POC_DIR"

    local prompt="${POC_PROMPT_TEMPLATE//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__RESULT_FILE__/$result}"
    prompt="${prompt//__SOURCE_FILE__/$f}"
    prompt="${prompt//__POC_DIR__/$POC_DIR}"

    poc_throttle

    (
        if claude -p "$prompt" \
            --model claude-sonnet-4-6 \
            --dangerously-skip-permissions \
            --allowedTools "Read,Write,Bash,Grep,Glob,Agent" \
            > "$POC_DIR/poc_session.log" 2>&1; then
            if grep -qE "You're out of extra usage|hit your (session|usage) limit" "$POC_DIR/poc_session.log" 2>/dev/null; then
                echo "[$(date '+%F %T')] POC USAGE-LIMIT $f" >> "$LOGFILE"
            else
                touch "$POC_DIR/.done"
                local verified
                verified=$({ grep -l "^VERIFIED" "$POC_DIR"/vuln_*_status.txt 2>/dev/null || true; } | wc -l | tr -d ' \n')
                echo "[$(date '+%F %T')] POC $f: $verified/$vuln_n verified" >> "$LOGFILE"
            fi
        else
            echo "[$(date '+%F %T')] POC ERR $f: claude exit $?" >> "$LOGFILE"
        fi
    ) &
    POC_PIDS+=($!)
    POC_LAUNCHED=$((POC_LAUNCHED + 1))
    echo "  -> launched PoC (bg pid=$!, running=${#POC_PIDS[@]}/$POC_PARALLEL)"
}

COUNT=0
VULN_COUNT=0
SKIPPED=0
ERRORS=0
EVENTS_SEEN=0
: > "$EVENTS_FILE"
rm -f "$STOP_FILE"

drain_events() {
    [ -f "$EVENTS_FILE" ] || return 0
    local total_lines
    total_lines=$(wc -l < "$EVENTS_FILE" | tr -d ' ')
    [ "$total_lines" -gt "$EVENTS_SEEN" ] || return 0

    local type ef etag eresult evn
    while IFS='|' read -r type ef etag eresult evn; do
        case "$type" in
            VULN)
                VULN_COUNT=$((VULN_COUNT + evn))
                echo "  -> [$ef] FOUND $evn vulnerability(ies)!"
                echo "[$(date '+%F %T')] VULN $ef: $evn findings" >> "$LOGFILE"
                launch_poc_bg "$ef" "$etag" "$eresult" "$evn"
                ;;
            CLEAN)
                echo "  -> [$ef] Clean."
                ;;
            ERROR)
                ERRORS=$((ERRORS + 1))
                echo "  -> [$ef] WARNING: empty result, removed" | tee -a "$LOGFILE"
                ;;
            ANOMALY)
                echo "  -> [$ef] WARNING: format anomaly (no '## VULN:' and no NO_VULN_FOUND) — flagged for review" | tee -a "$LOGFILE"
                echo "[$(date '+%F %T')] FORMAT-ANOMALY $ef" >> "$LOGFILE"
                ;;
            USAGE_LIMIT)
                echo ""
                echo "!!! USAGE LIMIT REACHED while auditing: $ef"
                echo "[$(date '+%F %T')] STOPPED: usage limit hit at $ef" >> "$LOGFILE"
                ;;
        esac
    done < <(tail -n "+$((EVENTS_SEEN + 1))" "$EVENTS_FILE")

    EVENTS_SEEN=$total_lines
}

audit_one() {
    local f="$1" tag="$2" result="$3"

    local prompt="${AUDIT_PROMPT_TEMPLATE//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__FILE__/$f}"

    claude -p "$prompt" \
        --model claude-sonnet-4-6 \
        --dangerously-skip-permissions \
        --allowedTools "Read,Grep,Glob,Agent" \
        > "$result" 2>&1

    if grep -qE "You're out of extra usage|hit your (session|usage) limit" "$result" 2>/dev/null; then
        rm -f "$result"
        touch "$STOP_FILE"
        echo "USAGE_LIMIT|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
        return 0
    fi

    if [ ! -s "$result" ]; then
        rm -f "$result"
        echo "ERROR|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
        return 0
    fi

    printf '\n<!-- %s: %s -->\n' "$VERSION_MARKER" "$PROMPT_VERSION" >> "$result"

    if grep -q "^## VULN:" "$result" 2>/dev/null; then
        local vuln_n
        vuln_n=$(grep -c "^## VULN:" "$result")
        echo "VULN|${f}|${tag}|${result}|${vuln_n}" >> "$EVENTS_FILE"
    elif grep -qi "NO_VULN_FOUND" "$result" 2>/dev/null; then
        echo "CLEAN|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    else
        echo "ANOMALY|${f}|${tag}|${result}|0" >> "$EVENTS_FILE"
    fi
}

echo "=========================================="
echo " FFmpeg Full Security Audit"
echo " Mode: $MODE  (audit=$RUN_AUDIT, poc=$POC_ENABLED, audit_parallel=$AUDIT_PARALLEL, poc_parallel=$POC_PARALLEL)"
echo " Files to audit: $TOTAL (skipped $MISSING missing)"
echo " Results: $OUTDIR/   PoCs: $POC_BASE/"
echo " Log: $LOGFILE"
echo "=========================================="
echo ""

if [ "$RUN_AUDIT" = "0" ]; then
    echo "Skipping audit phase (--poc-only) — scanning existing results for PoC launch..."
    for f in "${FILES[@]}"; do
        tag=$(tag_for "$f")
        result="$OUTDIR/${tag}.md"
        [ -f "$result" ] || continue
        grep -q "^## VULN:" "$result" 2>/dev/null || continue
        vuln_n=$(grep -c "^## VULN:" "$result")
        echo "[poc-only] $f ($vuln_n vuln)"
        launch_poc_bg "$f" "$tag" "$result" "$vuln_n"
    done
else
for f in "${FILES[@]}"; do
    if [ -f "$STOP_FILE" ]; then
        break
    fi

    COUNT=$((COUNT + 1))
    tag=$(tag_for "$f")
    result="$OUTDIR/${tag}.md"

    if result_is_current "$result"; then
        SKIPPED=$((SKIPPED + 1))
        if [ "$POC_ENABLED" = "1" ] && grep -q "^## VULN:" "$result" 2>/dev/null; then
            vuln_n=$(grep -c "^## VULN:" "$result")
            launch_poc_bg "$f" "$tag" "$result" "$vuln_n"
        fi
        continue
    elif [ -f "$result" ]; then
        echo "[$COUNT/$TOTAL] Stale (prompt-v$PROMPT_VERSION) re-auditing: $f"
        rm -f "$result"
    else
        echo "[$COUNT/$TOTAL] Auditing: $f"
    fi

    audit_throttle
    audit_one "$f" "$tag" "$result" &
    AUDIT_PIDS+=($!)
done

for pid in "${AUDIT_PIDS[@]+"${AUDIT_PIDS[@]}"}"; do
    wait "$pid" 2>/dev/null || true
done
drain_events

if [ -f "$STOP_FILE" ]; then
    echo ""
    echo "!!! Resume with: ./ffmpeg_audit.sh"
    echo ""
    echo "Waiting for in-flight PoC subagents to finish..."
    wait
    echo "=========================================="
    echo " Audit INTERRUPTED (usage limit)"
    echo " Completed: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL"
    echo " Vulnerabilities: $VULN_COUNT"
    echo " PoCs launched: $POC_LAUNCHED"
    echo " Resume: ./ffmpeg_audit.sh"
    echo "=========================================="
    rm -f "$STOP_FILE"
    exit 1
fi

echo ""
echo "=========================================="
echo " Audit Complete"
echo " Files audited: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL total"
echo " Errors: $ERRORS"
echo " Vulnerabilities found: $VULN_COUNT"
echo " Results: $OUTDIR/"
echo "=========================================="
echo "[$(date '+%F %T')] DONE: $((COUNT - SKIPPED)) new, $SKIPPED skipped, $VULN_COUNT vulns" >> "$LOGFILE"
fi

# ============================================================
# 等待所有后台 PoC 任务收尾
# ============================================================
if [ "$POC_ENABLED" = "1" ] && [ "${#POC_PIDS[@]}" -gt 0 ]; then
    echo ""
    echo "Waiting for ${#POC_PIDS[@]} background PoC subagent(s) to finish..."
    wait
fi

if [ "$POC_ENABLED" = "1" ]; then
    poc_done=$(find "$POC_BASE" -name '.done' 2>/dev/null | wc -l | tr -d ' \n')
    poc_verified=$({ grep -rl "^VERIFIED" "$POC_BASE"/ 2>/dev/null || true; } | wc -l | tr -d ' \n')
    poc_total=$(find "$POC_BASE" -name 'vuln_*_status.txt' 2>/dev/null | wc -l | tr -d ' \n')
    echo "=========================================="
    echo " PoC Generation Summary"
    echo " Launched this run:   $POC_LAUNCHED"
    echo " Already-done skip:   $POC_SKIPPED"
    echo " Files with .done:    $poc_done"
    echo " PoCs total/verified: $poc_total / $poc_verified"
    echo " Base: $POC_BASE/"
    echo "=========================================="
fi
