#!/bin/bash
# mp3gain 全量安全审计脚本（仅内存安全漏洞，*.c 文件）
#
# 用法:
#   ./mp3gain_audit.sh                        # 默认 resume 模式（审计 + PoC 生成）
#   ./mp3gain_audit.sh --restart              # 清除结果，从头开始
#   ./mp3gain_audit.sh --restart-from 5       # 从第5个文件开始
#   ./mp3gain_audit.sh --list-pending         # 仅列出未审计文件
#   ./mp3gain_audit.sh --stats                # 统计已有审计结果
#   ./mp3gain_audit.sh --no-poc               # 只审计，跳过 PoC 生成
#   ./mp3gain_audit.sh --poc-only             # 只跑 PoC 生成阶段（跳过审计）
#   ./mp3gain_audit.sh --restart-poc          # 清除已有 PoC，重新生成
#   ./mp3gain_audit.sh mp3gain.c             # 审计指定文件

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
SOURCE_DIR="/data/ylwang/non-textfuzz/target/mp3gain"
OUTDIR="/data/ylwang/non-textfuzz/target/_audit_result/mp3gain"
LOGFILE="$OUTDIR/audit.log"
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
    dir=$(dirname "$f" | tr "/" "_")
    [ "$dir" = "." ] && dir=""
    [ -n "$dir" ] && echo "${dir}_${name}" || echo "$name"
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
    SCAN_ROOT="$SOURCE_DIR"

    if [ ! -d "$SCAN_ROOT" ]; then
        echo "FATAL: scan root missing: $SCAN_ROOT" >&2
        exit 2
    fi
    if [ -z "$(find "$SCAN_ROOT" -name '*.c' -not -path '*/build_test/*' -print -quit)" ]; then
        echo "FATAL: scan root has no .c files: $SCAN_ROOT" >&2
        exit 2
    fi

    mapfile -t FILES < <(
        find "$SOURCE_DIR" -name '*.c' -not -path '*/build_test/*' \
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
    echo " mp3gain Audit Statistics"
    echo " Total source files:      $TOTAL"
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
AUDIT_PROMPT_TEMPLATE='你是一个顶级 C 安全审计专家，正在对 mp3gain（一个用于调整 MP3 音频增益/音量的命令行工具）进行授权安全审计，目标是发现可提交 bug bounty 的真实内存安全漏洞。

请仔细阅读文件 __SOURCE_DIR__/__FILE__ 的完整内容。
同时用 Grep/Glob/Read 查看相关的头文件、宏定义、调用的函数实现，以理解完整上下文。

**大文件必须多遍 / 分组深读——"一遍读完就判 clean"是历史漏报根因：**
- 若文件较大（≳500 行），不要一遍扫完就下结论。用 Read 工具分批读取（每批 400-600 行），逐组分析后**在自己的输出里**记录每组的发现，全部读完后汇总成 `## VULN:` 块。**不要派发 subagent**，全部在你自己的消息里完成，这样输出才能被正确捕获。
- 每个函数群都要追到边界条件（malloc 大小、数组索引、指针算术、整数溢出后的 malloc 大小参数）。

项目背景：
- mp3gain 是一个用 C 语言编写的命令行工具，用于无损调整 MP3 文件的音量（回放增益）。
- 源代码位于项目根目录（mp3gain.c、apetag.c、gain_analysis.c、id3tag.c、rg_error.c）以及 mpglibDBL/ 子目录下。
- 主要攻击面：攻击者在命令行传入精心构造的 MP3 文件给 mp3gain，触发内存安全漏洞。
  - 基本用法：mp3gain input.mp3（分析增益）
  - 递归调整：mp3gain -r input.mp3
- MP3 文件解析流程：
  - ID3v2 tag（文件头部，可选）："ID3" + version(2B) + flags(1B) + size(4B syncsafe)
  - MP3 帧：sync word(0xFFE0 mask) + 帧头(4B) + 帧数据
  - APE tag（文件尾部，可选）："APETAGEX" + version(4B LE) + size(4B LE) + count(4B LE) + flags(4B LE) + reserved(8B)
- 主要漏洞面：
  - ID3 tag 解析（id3tag.c）：tag size 字段（syncsafe integer）转换不正确导致超大 malloc，string 长度字段直接用于内存操作
  - APE tag 解析（apetag.c）：item count 字段来自文件，用于循环或预分配，超大值导致越界；item key/value 长度字段导致 OOB read/write
  - MP3 帧解析（mpglibDBL/）：帧长度计算错误导致 OOB read，位流解析中的越界访问
  - gain_analysis.c：输入样本缓冲区大小依赖于 MP3 帧参数

**重点关注以下内存安全漏洞类型（仅报告内存安全漏洞，不报告逻辑漏洞）：**

1. **整数溢出 → malloc 下分配**：malloc(length) 或 malloc(count * size) 中 length/count 来自文件未经校验，溢出导致 under-allocation 后越界写。
2. **ID3/APE tag 长度字段溢出**：tag item key length、value length 为文件字段，直接用于 malloc 或 memcpy，超大值导致 OOM 或堆溢出。
3. **堆缓冲区溢出**：memcpy/strcpy/strncpy 操作时源长度来自文件字段，目标缓冲区固定大小或已分配大小不足。
4. **越界读**：MP3 帧数据读取时帧长度报告值超过实际文件剩余字节，指针越过缓冲区边界。
5. **APE tag item 计数溢出**：APE tag item count 字段用于预分配或循环，超大值导致越界写。
6. **有符号/无符号截断**：uint32 被截断为 int32 或 uint16，负数偏移或错误大小。
7. **栈缓冲区溢出**：使用固定大小栈数组处理来自文件的可变长度数据。

不报告以下情形：
- 逻辑错误（错误的增益计算、元数据读写问题等）——本项目只审计内存安全。
- 仅在非默认编译选项下才能触发的问题。
- 纯假设性漏洞或已知 CVE 的重复。
- 仅造成 assert 失败但无内存破坏的问题。

主动使用工具获取上下文（必须执行以下步骤，不能跳过）：
1. 用 Grep 搜索关键函数调用点：grep -rn "函数名" __SOURCE_DIR__ --include="*.c" --include="*.h" --exclude-dir=build_test
2. 对处理外部输入（MP3 文件字节）的函数，追踪数据来源。
3. 对 malloc/realloc/calloc 调用，用 Grep 确认调用处是否有大小校验。
4. 关注 memcpy、strcpy、strncpy、sprintf、fread 等函数的使用。
5. 对 ID3/APE tag 解析代码，检查 length/count 字段是否有上界校验。

⚠️ malloc 溢出判据：只要在 malloc(expr) 前 expr 本身可以整数溢出（如 malloc(len + 1) 而 len 为 uint32 最大值，或 malloc(count * sizeof(T)) 而 count 来自文件），就算可达，要报告；只有当有明确的上界校验才判不可达。

==================== 最终输出契约（极其重要，违反则结果作废）====================
你这次任务的【最终回复，也就是最后一条消息】会被原样保存为审计报告，并被自动化脚本用 grep "^## VULN:" 解析来决定是否生成 PoC。因此必须严格遵守：
1. 每一个漏洞都必须是独立的块，以 `## VULN:` 开头（必须行首顶格，前面不能有任何字符），严格按下面"输出格式"逐字段输出。
2. 严禁用表格、散文段落或要点列表来"汇总"漏洞；严禁出现"我发现了 N 个漏洞""Final Summary""综上""下面是结论"之类的过渡话术。最终消息里除了若干 `## VULN:` 块（或单独的 NO_VULN_FOUND）之外，不要有任何其它内容。
3. 即使你使用了 subagent 协助分析，也必须把它们报告的每一个漏洞【全部重新整理】成完整的 `## VULN:` 块，在你自己的最终消息里逐条完整输出，绝不能只贴 subagent 给的表格、摘要或一句话结论。
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
- **攻击向量**: crafted MP3 file
- **外部触发路径**: <从入口到漏洞点的完整调用链，例如: mp3gain main() -> analyzeOneFile() -> id3tag_parse() -> ... -> vulnerable_func()>
- **描述**: xxx（说明漏洞成因——内存破坏机制）
- **触发条件**: xxx（攻击者需要构造怎样的 MP3 文件）
- **安全影响**: xxx（最坏情况下的利用后果：RCE/DoS/信息泄露/…）'

# ============================================================
# PoC 生成相关设置
# ============================================================
BIN="/data/ylwang/non-textfuzz/target/mp3gain/build_test/mp3gain"
POC_BASE="/data/ylwang/non-textfuzz/target/_poc/mp3gain"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=1
if [ "$RUN_POC" = "0" ]; then
    POC_ENABLED=0
elif [ ! -x "$BIN" ]; then
    echo "WARNING: $BIN not executable — PoC phase will be skipped."
    echo "         Build mp3gain first with ASAN+UBSAN, e.g.:"
    echo "           cd $SOURCE_DIR"
    echo "           mkdir -p build_test && cd build_test"
    echo "           make -C .. CC=clang CFLAGS='-fsanitize=address,undefined -g -O1' LDFLAGS='-fsanitize=address,undefined' BINDIR=\$(pwd)"
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

POC_PROMPT_TEMPLATE='你是 mp3gain 安全研究员。基于已有的漏洞审计报告，为每个漏洞生成可实际复现的 PoC。

==================== 硬性规则（违反则 PoC 无效）====================
本项目的 __BIN__ 已经是 ASAN+UBSAN 构建。
所有 PoC 必须通过这个真实二进制触发。

1. **严禁自写 harness**：
   - 不允许把漏洞函数抠出来单独编译成可执行文件
   - 不允许链接 mp3gain 内部头文件写任何 C/C++ 程序
   - 不允许通过任何方式编译新的 C/C++ 代码来触发漏洞
2. **唯一合法的漏洞触发途径**（只允许以下两种方式）：
   - 用 Python struct 模块构造精心设计的恶意 MP3 字节序列（vuln_NNN_gen.py），
   - 用 shell 脚本直接调用 mp3gain，并通过命令行选项（-r、-a、-c、-s r/i/a 等）调整执行路径（vuln_NNN_run.sh），
   - 让 ASAN/UBSAN 在真实执行路径中自行报错。
3. 唯一可接受的辅助文件：
   - vuln_NNN_gen.py：Python 脚本，只用 struct/bytes 构造 MP3/ID3/APE，绝不调用目标库函数
   - vuln_NNN_run.sh：Shell 脚本，调用 mp3gain [选项] 处理恶意 MP3
====================================================================

漏洞报告:   __RESULT_FILE__
源代码文件: __SOURCE_DIR__/__SOURCE_FILE__
PoC 目录:   __POC_DIR__
mp3gain 二进制: __BIN__

MP3/ID3/APE 文件基本结构（用于构造 PoC）：
- ID3v2 tag（文件头部，可选）：
  - Header: "ID3" + version(2B) + flags(1B) + size(4B syncsafe-integer, 每字节最高位为0)
  - Frame: frame_id(4B) + size(4B) + flags(2B) + data
  - 常用 frame IDs: "TIT2"(title), "TPE1"(artist), "COMM"(comment), "APIC"(picture)
  - COMM frame data: encoding(1B) + language(3B) + short_desc + 0x00 + text
- MP3 帧格式：
  - 同步字: 0xFF 0xFB（MPEG1 Layer3 128kbps）或 0xFF 0xE0（同步掩码 0xFFE0）
  - 帧头(4B): sync(11b) + version(2b) + layer(2b) + protection(1b) + bitrate_index(4b) + samplerate_index(2b) + padding(1b) + private(1b) + channel_mode(2b) + mode_ext(2b) + copyright(1b) + original(1b) + emphasis(2b)
  - 帧数据: side_info + main_data（长度由帧头字段计算）
  - 常用帧长度（MPEG1 Layer3 128kbps 44100Hz）= 417 或 418 字节
- APE tag（文件尾部或头部，可选）：
  - Header/Footer: "APETAGEX" + version(4B LE) + size(4B LE) + count(4B LE) + flags(4B LE) + reserved(8B)
    - version: 2000（APEv2）
    - flags bit 29 = 1 表示是 header，bit 29 = 0 表示是 footer
    - flags bit 31 = 1 表示有 header
  - Item: item_value_size(4B LE) + item_flags(4B LE) + item_key(variable, null-terminated) + item_value(variable)

==================== PoC 生成范围限制（必须严格执行）====================
下列情况**跳过 PoC，直接写 vuln_NNN_status.txt 第一行为 SKIPPED**，不生成任何运行脚本：
- 漏洞无法通过在命令行传入构造的 MP3 文件来触发（即需要修改源码才能到达）。
对于 SKIPPED 的漏洞：在 vuln_NNN_notes.md 里写明跳过原因，不生成 _run.sh 和 _result.txt。
======================================================================

步骤：
1. Read 漏洞报告，列出全部以 "## VULN:" 开头的漏洞条目，按出现顺序编号 1,2,3,...
2. **对每个漏洞并行派发一个 subagent**（一条消息内同时发出 N 个 Agent 调用，subagent_type=general-purpose）。
   每个 subagent 严格只负责自己那一个 VULN。

每个 subagent 必须完成：
A. 读懂对应 VULN 的函数/行号/触发条件，必要时 Read 源码与相关头文件。
   **首先判断是否命中上述 SKIPPED 条件**，命中则直接写 SKIPPED 状态并退出。
B. 在 __POC_DIR__/ 下生成（NNN 为 3 位零填编号）：
   - vuln_NNN_gen.py   —— Python 脚本，用 struct 模块构造恶意 MP3/ID3/APE 字节序列，
                          写入文件 __POC_DIR__/vuln_NNN.mp3。
                          根据漏洞触发条件精心设置字段值（如超大 ID3 frame size、
                          超大 APE item count、畸形帧长度字段等）。
   - vuln_NNN_run.sh   —— 可执行 shell，流程：
       1) 运行 vuln_NNN_gen.py 生成 vuln_NNN.mp3（若已存在则跳过）
       2) 运行 mp3gain 并捕获输出和 ASAN 日志
          （根据漏洞场景选择合适的调用方式）：
          # 分析增益模式：
          ASAN_OPTIONS="abort_on_error=0:log_path=__POC_DIR__/asan.log" \
            __BIN__ __POC_DIR__/vuln_NNN.mp3 \
            > __POC_DIR__/vuln_NNN_result.txt 2>&1 || true
          # 或递归调整模式：
          ASAN_OPTIONS="abort_on_error=0:log_path=__POC_DIR__/asan.log" \
            __BIN__ -r __POC_DIR__/vuln_NNN.mp3 \
            > __POC_DIR__/vuln_NNN_result.txt 2>&1 || true
       3) 从 asan.log.* 文件中 grep ASAN/UBSAN 错误并追加到 result.txt：
          for f in __POC_DIR__/asan.log.*; do
            [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
              >> __POC_DIR__/vuln_NNN_result.txt || true
          done
       示例框架：
         #!/bin/bash
         set -euo pipefail
         cd "__POC_DIR__"
         [ -f vuln_NNN.mp3 ] || python3 vuln_NNN_gen.py
         ASAN_OPTIONS="abort_on_error=0:log_path=./asan.log" \
           __BIN__ vuln_NNN.mp3 > vuln_NNN_result.txt 2>&1 || true
         for f in ./asan.log.*; do
           [ -f "$f" ] && grep -E "AddressSanitizer|ERROR:|runtime error:" "$f" \
             >> vuln_NNN_result.txt || true
         done
   - vuln_NNN_notes.md        —— 简短说明 PoC 思路、触发路径、预期现象
C. chmod +x vuln_NNN_run.sh，然后**实际运行它**：
       timeout 30 bash __POC_DIR__/vuln_NNN_run.sh
   验证通道：
   - 内存破坏类：ASAN "heap-buffer-overflow"、UBSAN "runtime error" 等出现在 result.txt 中
D. 根据 vuln_NNN_result.txt 判定，写 __POC_DIR__/vuln_NNN_status.txt：
   第一行必须是：
     VERIFIED_CRASH     —— ASAN/UBSAN 在真实 mp3gain 执行路径中报错
     UNVERIFIED         —— 跑通但无漏洞迹象
     ERROR              —— PoC 生成或运行本身报错
     SKIPPED            —— 命中跳过条件
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

    local prompt="${POC_PROMPT_TEMPLATE//__BIN__/$BIN}"
    prompt="${prompt//__SOURCE_DIR__/$SOURCE_DIR}"
    prompt="${prompt//__RESULT_FILE__/$result}"
    prompt="${prompt//__SOURCE_FILE__/$f}"
    prompt="${prompt//__POC_DIR__/$POC_DIR}"

    poc_throttle

    (
        if CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS=0 claude -p "$prompt" \
            --model claude-sonnet-4-6 \
            --dangerously-skip-permissions \
            --allowedTools "Read,Write,Bash,Grep,Glob,Agent" \
            > "$POC_DIR/poc_session.log" 2>&1; then
            if grep -qE "You're out of extra usage|hit your (session|usage) limit|Background tasks still running after" "$POC_DIR/poc_session.log" 2>/dev/null; then
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

    if grep -qE "You're out of extra usage|hit your (session|usage) limit|Background tasks still running after" "$result" 2>/dev/null; then
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
echo " mp3gain Full Security Audit"
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
    echo "!!! Resume with: ./mp3gain_audit.sh"
    echo ""
    echo "Waiting for in-flight PoC subagents to finish..."
    wait
    echo "=========================================="
    echo " Audit INTERRUPTED (usage limit)"
    echo " Completed: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL"
    echo " Vulnerabilities: $VULN_COUNT"
    echo " PoCs launched: $POC_LAUNCHED"
    echo " Resume: ./mp3gain_audit.sh"
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
