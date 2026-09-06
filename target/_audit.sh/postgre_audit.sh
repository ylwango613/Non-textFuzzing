#!/bin/bash
# PostgreSQL 全量安全审计脚本（仅 src/backend/ src/common/ src/port/ 生产代码）
#
# 用法:
#   ./audit.sh                        # 默认 resume 模式（审计 + PoC 生成）
#   ./audit.sh --restart              # 清除结果，从头开始
#   ./audit.sh --restart-from 50      # 从第50个文件开始
#   ./audit.sh --list-pending         # 仅列出未审计文件
#   ./audit.sh --stats                # 统计已有审计结果
#   ./audit.sh --no-poc               # 只审计，跳过 PoC 生成
#   ./audit.sh --poc-only             # 只跑 PoC 生成阶段（跳过审计）
#   ./audit.sh --restart-poc          # 清除已有 PoC，重新生成
#   ./audit.sh src/backend/parser/gram.c   # 审计指定文件

set -euo pipefail

export PATH="$HOME/.nvm/versions/node/v20.19.6/bin:$HOME/.local/bin:$HOME/bin:$PATH"

PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTDIR="$PROJECT_DIR/audit-results"
LOGFILE="$PROJECT_DIR/audit.log"
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
        "$PROJECT_DIR/src/backend"
        "$PROJECT_DIR/src/common"
        "$PROJECT_DIR/src/port"
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
            ! -path '*/test/*' \
            ! -path '*/snowball/*' \
            ! -path '*/po/*' \
            | sed "s|^$PROJECT_DIR/||" | sort
    )
fi

VALID_FILES=()
MISSING=0
for f in "${FILES[@]}"; do
    if [ -f "$PROJECT_DIR/$f" ]; then
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
    echo " PostgreSQL Audit Statistics"
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
AUDIT_PROMPT_TEMPLATE='你是一个顶级 C 安全审计专家，正在对 PostgreSQL（最新开发版本，src/backend/ 核心引擎代码）进行授权安全审计，目标是发现可提交 bug bounty 的真实安全漏洞。

请仔细阅读文件 __PROJECT_DIR__/__FILE__ 的完整内容。
同时用 Grep/Glob/Read 查看相关的头文件（src/include/）、宏定义、调用的函数实现，以理解完整上下文。

**大文件必须多遍 / 分组深读——"一遍读完就判 clean"是历史漏报根因：**
- 若文件较大（≳1000 行，如 executor/execMain.c、parser/gram.c、optimizer/path/costsize.c、
  storage/page/heapam.c、backend/utils/adt/*.c），
  不要一遍扫完就下结论。按函数群拆分，**并行派发多个 subagent**（一条消息内同时发出 N 个 Agent 调用，
  subagent_type=general-purpose），每个 subagent 深读一个函数群并各自独立找漏洞；
  你再把它们的发现【全部重新整理】成 `## VULN:` 块（见末尾输出契约第 3 条）。
- 每个函数群都要追到边界条件（StringInfo 长度、palloc 大小、数组索引、递归深度、
  整数溢出后的 palloc0/repalloc 大小参数）。

**跨文件 / 跨子系统交互必查：**
- 本文件持有的指针/缓冲区（Relation、Buffer、HeapTuple、List、StringInfo）在事务回滚、
  relcache invalidation、catalog 变更、并发 vacuum/autovacuum、锁升级 / 降级后是否变悬空。
- Buffer pin/unpin 生命周期 × 并行执行 worker、WAL replay × 并发写事务、
  GIN/GiST/BRIN 索引并发扫描 × 页分裂、autovacuum × 长事务残留 dead tuple 等组合要看。
- 发现跨文件类漏洞时，在"外部触发路径"里写清楚跨文件的事件时序（先做 A 再做 B 才触发）。

项目背景：
- PostgreSQL 是一个标准 SQL 关系型数据库服务器，通过 TCP（libpq 协议）或 UNIX socket
  接受客户端连接，每个连接 fork 一个 backend 进程处理请求。
  作为广泛部署的数据库，常常直接对最终用户暴露 SQL 执行能力
  （Web 应用的后端数据库、云托管 PostgreSQL 服务、多租户 SaaS 系统）。
- 核心代码在 src/backend/ 下：
  - parser/    ：词法/语法解析（gram.y / scan.l）、raw parse tree 构建
  - nodes/     ：所有 AST / plan / executor 节点的定义与拷贝/序列化
  - optimizer/ ：查询重写（rewrite/ 在 backend/rewrite/）、逻辑优化、路径代价估算、
                 join 顺序、sublink/subplan 转换
  - executor/  ：物理执行算子（SeqScan、IndexScan、Hash、Sort、Agg、WindowAgg…）、
                 tuple table slot、expression evaluation (execExpr*)
  - storage/   ：页存储格式（heap/、页面 PageHeader）、buffer manager、
                 freespace map、visibility map、WAL（xlog*、rmgr/）、
                 lock manager（lmgr/）、SMgr（smgr.c）
  - access/    ：heap tuple CRUD（heapam.c）、各类索引 AM（btree、hash、gin、gist、spgist、brin）
  - catalog/   ：系统表读写、RelationBuildDesc、syscache、relcache、
                 pg_attribute / pg_type / pg_class 等
  - utils/     ：内置类型实现（adt/）、表达式解析辅助（cache/、fmgr/）、
                 内存管理（palloc/MemoryContext）、排序（sort/）、hash（hash/）
  - libpq/     ：后端协议处理（pqcomm.c / pqformat.c）
  - tcop/      ：postgres.c 主循环（ReadCommand / PortalRun）
  - replication/：WAL sender/receiver、logical decoding
  - jit/       ：LLVM JIT 代码生成
  - postmaster/：postmaster.c 主进程、子进程管理
- 主要攻击面：
  1) **不可信 SQL 字符串**：攻击者控制 SQL（Web 应用 SQL 注入内部片段、
     超级用户执行恶意 SQL、psql 直连的远程攻击者）。
  2) **不可信数据文件**：COPY FROM 读取攻击者控制的 CSV/binary 格式文件；
     pg_restore 解析恶意 pg_dump 归档文件。
  3) **网络协议**：攻击者直接发送畸形 libpq 消息（message type / length field /
     parameter encoding）给 PostgreSQL backend，触发 pqcomm.c / pqformat.c 里的解析漏洞。
  4) **不可信扩展/函数**：LOAD 一个恶意共享库，或调用 UNTRUSTED PL（plpython3u / plperlu）
     执行任意代码（这本身是设计行为，但通过它触发内核漏洞仍属范围内）。

**漏洞范围包含两大类，都要主动找：**
1. **内存安全漏洞**：堆/栈溢出、UAF、Double Free、整数溢出（特别是 palloc(n*m) 前未检查乘法溢出）、
   越界读写、未初始化读取（palloc vs palloc0 误用）。
2. **逻辑安全漏洞**：权限绕过（row security policy 被绕过、SET ROLE 边界失效、
   security definer 函数中的 search_path 注入）、事务隔离破坏（幻读/脏读）、
   约束绕过（UNIQUE/CHECK/NOT NULL/FK 在某些执行路径被跳过）、
   查询结果错误（planner 重写产生语义不同的结果，下游应用基于错误结果做安全决策）、
   WAL replay 异常留下不一致状态。

不报告以下情形：
- 仅在非默认编译选项下才能触发的问题。
- 纯假设性漏洞或已知 CVE 的重复。
- 仅造成 assert 失败但无内存破坏暗示的 DoS（除非在 release 构建下退化为真实越界）。
- 纯粹的资源耗尽型 DoS，除非有明显偏离预期的复杂度放大。

⚠️ palloc 溢出判据：只要在 palloc(expr) 前 expr 本身可以整数溢出（如 palloc(n * sizeof(T))
而 n 来自外部未经校验），就算可达，要报告；只有当乘法前有明确的 n <= MAX 校验才判不可达。

主动使用工具获取上下文（必须执行以下步骤，不能跳过）：
1. 用 Grep 搜索该文件中关键函数的调用点：grep -rn "函数名" src/ --include="*.c" --include="*.h"
2. 对处理外部输入的函数，追踪数据来源：是来自 parser/gram.y 的 token？还是从磁盘 page/WAL 读取的字节？
   还是从 libpq 协议消息直接传入？还是从 COPY 数据流读取？
3. 对 palloc/repalloc/palloc_array 调用，用 Grep 确认调用处是否有大小校验。
4. 用 Grep 搜索关键宏/常量定义（如 MaxAllocSize、BLCKSZ、MaxHeapTuplesPerPage、
   MaxTupleAttributeNumber 等）。
5. 关注 Assert() 标记附近是否隐藏了未在 release 构建校验的边界。

PostgreSQL 历史上常见的真实漏洞模式——请主动用 Grep 在当前文件及其调用链中搜索这些模式：

**内存安全类：**
- **palloc 整数溢出**：palloc(n * size) 或 palloc(n + k) 中 n 来自外部未经 MaxAllocSize 校验，
  乘法或加法溢出为小值，导致 under-allocation 后越界写。
- **StringInfo 越界**：appendStringInfo / appendBinaryStringInfo 系列在追加大量数据时
  enlargeStringInfo 未正确处理长度上限，或 StringInfo.len 字段整数溢出。
- **堆 page 解析越界**：storage/page/heapam.c 等读取 page 内 ItemId offset/length 字段时，
  恶意磁盘文件（直接写入 pg_class 数据文件、COPY binary 格式）可伪造字段导致越界读写。
- **COPY binary 格式解析**：COPY FROM BINARY 读取 attnum、tuple_data_length 等字段未校验，
  导致越界读写或 palloc 溢出。
- **GIN/GiST/BRIN/SP-GiST 索引页解析**：页内 offset/count 字段来自磁盘（可被恶意文件伪造），
  解析函数未校验就用于数组下标或 memcpy 长度。
- **WAL record 解析越界**：xlog 记录中的 data_length / block_data_length 字段未校验，
  WAL replay 时越界读写。
- **to_char / to_timestamp / format() 格式字符串**：格式化函数在处理超长格式字符串或
  特定转换说明符时发生缓冲区溢出（历史上有多个真实 CVE）。
- **表达式求值中的递归栈溢出**：深度嵌套的 CASE WHEN / 递归 CTE / 函数调用 / 子查询
  在 expression evaluator（execExpr*.c）中未做深度限制。
- **排序/哈希算子中的越界**：tuplesort / tuplestore / ExecHashJoin 等在处理 varlena 类型
  或宽元组时的缓冲区管理。
- **类型输入函数（array_in / range_in / record_in 等）**：解析外部文本表示时发生
  palloc 溢出或越界写（这类历史 CVE 最多）。
- **pg_restore / pg_dump 格式解析**：TOC / large-object dump 格式中的长度字段。

**逻辑安全类（必查）：**
- **Row Security Policy (RLS) 绕过**：通过 COPY TO/FROM、INSERT ... RETURNING、
  某些 inheritance 路径、触发器、规则（pg_rewrite）绕过 RLS 策略。
- **security definer 函数中的 search_path 注入**：未设置 SET search_path 的
  SECURITY DEFINER 函数被低权限用户通过在 search_path 前缀 schema 注入函数/类型来劫持。
- **权限检查顺序错误**：ACL 检查在某些代码路径中被 short-circuit 跳过，导致无权限用户
  可以读写表/视图/序列/函数（历史上多次出现）。
- **NOT NULL/CHECK/UNIQUE/FK 约束绕过**：通过 ALTER TABLE ... ADD CONSTRAINT NOT VALID、
  COPY FROM、某些 UPDATE 路径或并发场景绕过约束检查。
- **事务隔离 / MVCC 破坏**：snapshot 管理错误导致事务读到不该读的数据版本（信息泄露）或
  更新丢失（数据完整性）。
- **超级用户权限提升**：低权限用户通过函数调用、SET ROLE、CREATE EXTENSION、
  COPY TO/FROM PROGRAM 等路径获得超级用户权限。
- **planner 重写产生错误结果**：subquery flattening、view expansion、rule rewriting、
  constant folding 在 NULL 语义或三值逻辑边界条件下产生与标准 SQL 不一致的结果。

重点关注以下漏洞类型：

内存安全：
1. **RCE via palloc 溢出**：可通过 SQL 或 COPY 文件触发的 palloc 整数溢出导致堆腐败。
2. **堆缓冲区溢出/下溢**：类型输入函数、COPY 解析、WAL replay、索引页解析。
3. **整数溢出**：length/count 字段乘法溢出、有符号无符号转换（int32/int64 边界）。
4. **UAF**：Buffer pin/unpin 错误、relcache invalidation 后悬空指针、
   事务结束后 MemoryContext 释放但仍被引用。
5. **栈溢出**：表达式/子查询/CTE/PL/pgSQL 嵌套递归。
6. **未初始化读取**：palloc（非 palloc0）后未完全初始化的字段被序列化或传递给比较函数。
7. **磁盘页格式校验不足**：page header、ItemId、heap tuple header、各索引 AM 页格式。
8. **并发/竞态**：backend 进程间共享内存（Lock、ProcArray、WAL buffer）并发访问错误。

逻辑/语义安全：
9. **权限绕过**：ACL、RLS、schema 权限、SECURITY DEFINER 被绕过。
10. **约束绕过**：UNIQUE/CHECK/NOT NULL 在某些路径被跳过。
11. **SQL 语义错误结果**：planner 重写 / 窗口函数 / 聚合在边界条件下错误。
12. **权限提升**：低权限用户获得超级用户或其他用户权限。
13. **事务/WAL 异常路径**留下不一致状态。
14. **算法复杂度攻击**：恶意 SQL 触发指数级 join 规划或无限递归展开。

评估原则：
- 只报告高置信度漏洞（宁可漏报，不要误报）。
- 攻击向量必须属于：恶意 SQL / COPY 数据 / 恶意数据库文件 / 畸形 libpq 协议消息 之一。
- 对每个漏洞评估 CVSS v3.1 分数及对应 CWE 编号。
- 严重程度参考 CVSS：Critical(9.0-10.0) / High(7.0-8.9) / Medium(4.0-6.9) / Low(0.1-3.9)。
- 逻辑漏洞同样必须报告，不要因为没有内存破坏就忽略权限绕过、约束绕过、错误查询结果等问题。
  报告时在"漏洞类别"字段写明 memory-safety 或 logic。
- 如果没有发现可被外部触发的漏洞，输出：NO_VULN_FOUND

==================== 最终输出契约（极其重要，违反则结果作废）====================
你这次任务的【最终回复，也就是最后一条消息】会被原样保存为审计报告，并被自动化脚本用 grep "^## VULN:" 解析来决定是否生成 PoC。因此必须严格遵守：
1. 每一个漏洞都必须是独立的块，以 `## VULN:` 开头（必须行首顶格，前面不能有任何字符），严格按下面"输出格式"逐字段输出。
2. 严禁用表格（形如 | ... | 的 Markdown 表）、散文段落或要点列表来"汇总"漏洞；严禁出现"我发现了 N 个漏洞""Final Summary""综上""下面是结论"之类的过渡话术。最终消息里除了若干 `## VULN:` 块（或单独的 NO_VULN_FOUND）之外，不要有任何其它内容。
3. 即使你使用了 subagent 协助分析，也必须把它们报告的每一个漏洞【全部重新整理】成完整的 `## VULN:` 块，在你自己的最终消息里逐条完整输出，绝不能只贴 subagent 给的表格、摘要或一句话结论。
4. 没有发现任何可被外部触发的漏洞时，最终消息【只输出一行】：NO_VULN_FOUND
==================================================================================

输出格式（每个漏洞一个块）：
## VULN: <简短英文标题>
- **漏洞类别**: memory-safety / logic
- **函数**: xxx()
- **行号**: xxx-xxx
- **CWE**: CWE-XXX (名称)
- **CVSS v3.1**: X.X (AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H 等，根据攻击向量选择)
- **严重程度**: Critical/High/Medium/Low
- **攻击向量**: malicious SQL / COPY data / malicious DB file / malformed libpq message
- **外部触发路径**: <从入口到漏洞点的完整调用链，例如: psql -> ParseQuery -> ... -> vulnerable_func()>
- **描述**: xxx（说明漏洞成因——内存破坏机制 或 被破坏的语义不变式）
- **触发条件**: xxx（攻击者需要构造怎样的 SQL / COPY 文件 / 协议消息）
- **安全影响**: xxx（最坏情况下的利用后果：RCE/信息泄露/权限提升/约束绕过/错误结果误导上层应用/DoS/…）'

# ============================================================
# PoC 生成相关设置
# ============================================================
POSTGRES_BIN="$PROJECT_DIR/build/bin/postgres"
PSQL_BIN="$PROJECT_DIR/build/bin/psql"
INITDB_BIN="$PROJECT_DIR/build/bin/initdb"
PG_CTL_BIN="$PROJECT_DIR/build/bin/pg_ctl"
POC_BASE="$OUTDIR/poc"
POC_PARALLEL="${POC_PARALLEL:-3}"
AUDIT_PARALLEL="${AUDIT_PARALLEL:-3}"
EVENTS_FILE="$OUTDIR/.audit_run_events"
STOP_FILE="$OUTDIR/.audit_usage_limit_stop"

POC_ENABLED=1
if [ "$RUN_POC" = "0" ]; then
    POC_ENABLED=0
elif [ ! -x "$POSTGRES_BIN" ]; then
    echo "WARNING: $POSTGRES_BIN not executable — PoC phase will be skipped."
    echo "         Build PostgreSQL first with ASAN:"
    echo "           ./configure --prefix=\$PWD/build/debug --enable-cassert \\"
    echo "             CFLAGS='-fsanitize=address,undefined -g -O1' CC=clang"
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

POC_PROMPT_TEMPLATE='你是 PostgreSQL 安全研究员。基于已有的漏洞审计报告，为每个漏洞生成可实际复现的 PoC。

==================== 硬性规则（违反则 PoC 无效）====================
本项目的 __PROJECT_DIR__/build/bin/postgres 已经是 ASAN+UBSAN 构建。
所有 PoC 必须通过这个真实二进制触发。

1. **禁止自写 harness**：绝对不允许把漏洞函数抠出来单独编译，也不允许链接 PostgreSQL 内部头文件写 C 程序。
1a. **禁止修改 PostgreSQL 源码**：不得在 src/**/*.c 里加 wrapper 或去掉校验。
2. **内存漏洞的唯一合法验证途径**：
   - 通过 __PROJECT_DIR__/build/bin/psql 连接临时服务器执行 SQL，或
   - 通过 postgres --single 单用户模式执行 SQL，或
   - 通过 psql 执行包含 COPY FROM 的语句读取恶意数据文件，
   让 ASAN/UBSAN 在真实执行路径中自行报错。
3. 逻辑漏洞只能通过真实 psql/psql 接口复现，用差分对比方式验证语义不变式被破坏。
4. 唯一可接受的非 PostgreSQL 程序是：
   - 用 Python 生成恶意 COPY binary 文件或恶意 .pgdata 页文件的脚本（vuln_NNN_gen.py），
     只用二进制编辑方式构造恶意输入，绝不能调用 PostgreSQL 内部函数/头文件。
   - 用 initdb/pg_ctl 初始化和管理临时实例的 shell 脚本（已在 run.sh 中封装）。
====================================================================

漏洞报告:   __RESULT_FILE__
源代码文件: __PROJECT_DIR__/__SOURCE_FILE__
PoC 目录:   __POC_DIR__
二进制目录: __PROJECT_DIR__/build/bin/
  postgres : __PROJECT_DIR__/build/bin/postgres
  psql     : __PROJECT_DIR__/build/bin/psql
  initdb   : __PROJECT_DIR__/build/bin/initdb
  pg_ctl   : __PROJECT_DIR__/build/bin/pg_ctl

==================== PoC 生成范围限制（必须严格执行）====================
下列情况**跳过 PoC，直接写 vuln_NNN_status.txt 第一行为 SKIPPED**，不生成任何运行脚本：
- 攻击向量需要"malicious DB file"（恶意磁盘页文件 / pg_dump 归档 / 直接写 pgdata 文件）才能触发；
  纯 SQL 或 COPY FROM（CSV/text/binary 格式通过 psql 发送）不属于此限制，可以生成。
- 触发漏洞需要 PostgreSQL 超级用户（superuser）权限。
  如果漏洞在"普通登录用户（non-superuser）"可达的路径上，则允许生成。
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
   - 输入文件，至少其中一种：
     * vuln_NNN.sql           —— SQL 攻击向量
     * vuln_NNN_gen.py + 对应恶意文件 —— COPY binary / 恶意数据文件攻击向量
   - vuln_NNN_run.sh          —— 可执行 shell，流程：
       1) 用 initdb 在 __POC_DIR__/pgdata_NNN/ 初始化临时数据目录（若已存在则跳过）
       2) 用 pg_ctl 在随机端口（避免冲突，如 $((55432 + NNN_NUMBER))）启动 postgres
       3) 用 psql 执行 PoC SQL（或执行 COPY 加载恶意文件）
       4) 用 pg_ctl 停止实例
       5) 退出前保留 ASAN 报错输出
       示例框架：
         #!/bin/bash
         set -euo pipefail
         cd "$(dirname "$0")"
         PGDATA=__POC_DIR__/pgdata_NNN
         PGPORT=$((55432 + NNN_NUMBER))
         PGLOG=__POC_DIR__/pgdata_NNN/postgres.log
         INITDB=__PROJECT_DIR__/build/bin/initdb
         PGCTL=__PROJECT_DIR__/build/bin/pg_ctl
         PSQL=__PROJECT_DIR__/build/bin/psql
         PGSOCKET=__PROJECT_DIR__/build/run
         [ -d "$PGDATA" ] || "$INITDB" -D "$PGDATA" --no-locale -E UTF8
         "$PGCTL" -D "$PGDATA" -l "$PGLOG" -o "-p $PGPORT -k $PGSOCKET" start
         "$PSQL" -h "$PGSOCKET" -p $PGPORT postgres < vuln_NNN.sql || true
         "$PGCTL" -D "$PGDATA" stop || true
         grep -E "AddressSanitizer|UndefinedBehaviorSanitizer|runtime error" "$PGLOG" || true
   - vuln_NNN_notes.md        —— 简短说明 PoC 思路、触发路径、预期现象
C. chmod +x vuln_NNN_run.sh，然后**实际运行它**：
       timeout 120 bash __POC_DIR__/vuln_NNN_run.sh > __POC_DIR__/vuln_NNN_result.txt 2>&1
       echo "EXIT=$?" >> __POC_DIR__/vuln_NNN_result.txt
   验证通道：
   - 内存破坏类：ASAN "heap-buffer-overflow"、UBSAN "runtime error" 等
   - 逻辑类：差分对比显示语义不变式被违反（把"预期 vs 实际"的 diff 写进 result.txt）
D. 根据 vuln_NNN_result.txt 判定，写 __POC_DIR__/vuln_NNN_status.txt：
   第一行必须是：
     VERIFIED_CRASH     —— ASAN/UBSAN 在真实 postgres 执行路径中报错
     VERIFIED_BEHAVIOR  —— 无崩溃但有明确异常行为（差分对比证实语义被违反）
     UNVERIFIED         —— 跑通但无漏洞迹象
     ERROR              —— PoC 生成或运行本身报错
E. 不要修改 __POC_DIR__ 以外的任何文件，不要修改源码。
F. 运行结束后清理临时服务器进程（pg_ctl stop）。

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

    local prompt="${POC_PROMPT_TEMPLATE//__PROJECT_DIR__/$PROJECT_DIR}"
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

    local prompt="${AUDIT_PROMPT_TEMPLATE//__PROJECT_DIR__/$PROJECT_DIR}"
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
echo " PostgreSQL Full Security Audit"
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
    echo "!!! Resume with: ./audit.sh"
    echo ""
    echo "Waiting for in-flight PoC subagents to finish..."
    wait
    echo "=========================================="
    echo " Audit INTERRUPTED (usage limit)"
    echo " Completed: $((COUNT - SKIPPED)) new + $SKIPPED skipped / $TOTAL"
    echo " Vulnerabilities: $VULN_COUNT"
    echo " PoCs launched: $POC_LAUNCHED"
    echo " Resume: ./audit.sh"
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
