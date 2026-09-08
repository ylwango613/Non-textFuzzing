`dvdata.c` 는 전체 237줄로, 순수 정적 상수 배열 6개만 포함합니다:

- `ff_dv_zigzag248_direct[64]`
- `ff_dv_quant_shifts[22][4]`
- `ff_dv_quant_offset[4]`
- `ff_dv_vlc_len[NB_DV_VLC]` (NB_DV_VLC = 409)
- `ff_dv_vlc_run[NB_DV_VLC]`
- `ff_dv_vlc_level[NB_DV_VLC]`

실행 코드(함수, 루프, 분기, 포인터 연산, 메모리 할당)가 전혀 없습니다. 모든 값은 컴파일 타임 상수이며 외부 입력을 처리하는 경로가 존재하지 않습니다. 따라서 이 파일에서 외부 트리거 가능한 메모리 안전 취약점은 없습니다.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
