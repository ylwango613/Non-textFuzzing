분석이 완료되었습니다. 최종 결과를 정리합니다.

**분석 요약**

`parser.c` 자체(362줄)와 그 직접 콜체인(`parse_nal_units → ff_hevc_decode_nal_pps → ps_init_rps`)을 추적한 결과:

- `hevc_find_frame_end`의 bit-manipulation 로직 — 정상
- `hevc_parse_slice_header`의 `pps_id` 범위 체크 — 정상
- `sps->log2_max_poc_lsb` 경계 체크 — 16으로 제한, 정상
- `output_window` 오프셋 합산 — `read_window` + INT_MAX 기반 재검증으로 보호
- `ff_hevc_decode_extradata`의 nalsize 계산 — 정상(uint16 + 2 = 최대 65537, int 범위 내)
- **`pic_area_in_ctbs = sps->ctb_width * sps->ctb_height`** — **signed int overflow → heap underallocation → OOB read/write** (확인됨)

## VULN: Integer overflow in pic_area_in_ctbs leads to heap OOB read/write in ff_hevc_decode_nal_pps
- **취약점 유형**: memory-safety
- **함수**: `ff_hevc_decode_nal_pps()` (libavcodec/hevc/ps.c), triggered via `parse_nal_units()` (libavcodec/hevc/parser.c)
- **행호**: ps.c:2119 (overflow), ps.c:2167 (OOB access); parser.c:209–212 (call site)
- **CWE**: CWE-190 (Integer Overflow or Wraparound) → CWE-122 (Heap-based Buffer Overflow)
- **CVSS v3.1**: 8.8 (AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)
- **심각도**: High
- **공격 벡터**: crafted HEVC media file (raw Annex B or containerized HEVC stream)
- **외부 트리거 경로**: `ffmpeg -i <crafted_hevc> -f null -` → `avformat_open_input()` → HEVC parser → `hevc_parse()` → `parse_nal_units()` → `ff_hevc_decode_nal_pps()` (HEVC_NAL_PPS case) → `pps_init_rps()` → `sps->ctb_width * sps->ctb_height` overflows → `av_malloc_array(pic_area_in_ctbs, ...)` underallocates → tile_id loop at ps.c:2167 performs OOB read on `ctb_addr_rs_to_ts[]` and OOB write on `tile_id[]`
- **설명**: `ff_hevc_decode_nal_pps`(ps.c:2119)에서 `pic_area_in_ctbs = sps->ctb_width * sps->ctb_height`를 `int` 곱셈으로 계산한다. `av_image_check_size`가 각 차원을 개별적으로만 검사하고 면적을 검사하지 않으므로, 예를 들어 `width = height = 1,048,577`(log2_ctb_size=4)을 지정하면 `ctb_width = ctb_height = 65537`이 되고, `65537 × 65537 = 4,295,098,369`가 int32로 오버플로되어 `131,073`으로 잘린다. `av_malloc_array(131073, 4)`는 ~512 KB만 할당하지만, ps.c:2163–2167의 타일 루프는 `y`를 0~65536, `x`를 0~65536으로 반복하며 `ctb_addr_rs_to_ts[y * 65537 + x]`를 접근한다(최대 인덱스 ≈ 4.29 billion). 할당 크기(131073)를 수십억 요소 초과하는 힙 OOB 읽기가 발생하고, 그 읽기값을 `tile_id[]` 쓰기의 인덱스로 사용하므로 공격자가 제어할 수 있는 힙 OOB 쓰기로 이어진다.
- **트리거 조건**: 공격자가 SPS에 `pic_width_in_luma_samples = pic_height_in_luma_samples = 1,048,577`, `log2_min_luma_coding_block_size_minus3 = 0`(→ log2_min_cb_size=3), `log2_diff_max_min_luma_coding_block_size = 1`(→ log2_ctb_size=4)로 설정한 HEVC 비트스트림을 구성하면 `ctb_width = ctb_height = 65537`이 된다. `av_image_check_size` 검사(stride 기반)는 해당 차원에서 통과하므로 추가 전제 조건이 없다.
- **보안 영향**: 힙 OOB 읽기 + OOB 쓰기로 인해 힙 메타데이터/인접 객체가 손상될 수 있으며, 공격자가 구성한 비트스트림 하나로 원격 코드 실행(RCE)까지 이어질 수 있다. `ffmpeg -i <file>`를 실행하는 것만으로도 트리거된다.

<!-- AUDIT_PROMPT_VERSION: 1 -->
