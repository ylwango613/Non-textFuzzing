The bytestream2 put functions are bounds-checked (lines 62–66), so the output buffer is safe. The real issue lies in the `do...while` loop control.

**Key finding:** In `pcm_dvd_encode_frame`, when `frame->nb_samples < s->samples_per_block`, the expression `blocks = (frame->nb_samples / s->samples_per_block) * s->block_size / s->block_size` computes to **0**. The `do { ... } while (--blocks)` idiom is used throughout (lines 151–165). A `do...while` always executes the body **at least once** — so with `blocks = 0`, the body runs, then `--blocks = -1` (non-zero), and the loop continues, wrapping through signed integer overflow (UB) for ~2³² iterations. Each iteration advances `src32` past `frame->data[0]`, causing an unbounded OOB heap read and a near-infinite CPU spin.

This is triggered in:
- **S32 mono** (line 143): `samples_per_block=4` → `blocks=0` when `frame->nb_samples ∈ {1,2,3}`
- **S32 6-channel** (default case, line 97): `samples_per_block=4` → same
- **S32 stereo** (line 84): `samples_per_block=2` → `blocks=0` when `frame->nb_samples=1`

The last frame of any audio clip whose total length is not a multiple of the encoder's `frame_size` (e.g. 28 for 6ch/S32/96kHz) will land in this path. The bytestream2 writes are safe (bounds-checked), but `src32` reads become unbounded heap reads.

---

## VULN: do-while-blocks-zero OOB heap read and near-infinite loop in S32 encoding path
- **漏洞类别**: memory-safety
- **函数**: pcm_dvd_encode_frame()
- **行号**: 119-165
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 6.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: Medium
- **攻击向量**: crafted media file (triggering pcm_dvd transcoding)
- **外部触发路径**: `ffmpeg -i crafted.mkv -c:a pcm_dvd output.vob` → `avcodec_send_frame()` → `pcm_dvd_encode_frame()` → `do { ... } while(--blocks)` with `blocks=0`
- **描述**: `pcm_dvd_encode_frame()` computes `pkt_size` (line 119) and `blocks` (line 120) using integer division `frame->nb_samples / s->samples_per_block`. When `frame->nb_samples < s->samples_per_block` (e.g., 1–3 for `samples_per_block=4`), this division yields 0, so `blocks=0`. The S32 encoding loops on lines 151–165 use the `do { ... } while (--blocks)` idiom, which always executes the body at least once before testing the exit condition. After the first body execution `--blocks` produces `-1` (non-zero), so the loop continues. Each iteration unconditionally reads `src32[0]`, `src32[1]` and advances `src32` by 4 (2 samples per inner-loop pass), reading progressively deeper into heap memory past the end of `frame->data[0]`. The signed integer decrement from `INT_MIN` to `INT_MIN-1` is undefined behavior; in practice the loop runs approximately 2³² iterations (≈4 billion), constituting a CPU-time denial of service alongside the OOB heap read. The bytestream2 write functions are bounds-checked and do not overflow the output buffer; the vulnerability is purely on the source audio data side.
- **触发条件**: Attacker provides a crafted multi-channel (e.g., 5.1 or stereo) S32 audio file (e.g., MKV/WAV/FLAC) whose total sample count is not a multiple of the pcm_dvd encoder's `frame_size` (e.g., `frame_size=28` for 6-channel/S32/96kHz). The resulting last frame will have 1–3 samples, causing `blocks=0`. Victim must transcode with `-c:a pcm_dvd` (e.g., `ffmpeg -i crafted.mkv -c:a pcm_dvd out.vob`). No special privileges or codec flags needed beyond specifying the pcm_dvd output codec.
- **安全影响**: (1) **DoS**: near-infinite loop (~2³² iterations) consuming 100% CPU until process is killed or the OOB reads eventually fault on an unmapped page and crash the process. (2) **Heap information disclosure**: up to several GB of heap memory read past `frame->data[0]` before crash; with careful crafting in a multi-threaded application this could leak sensitive heap contents (keys, tokens, other frames' decoded data).

<!-- AUDIT_PROMPT_VERSION: 1 -->
