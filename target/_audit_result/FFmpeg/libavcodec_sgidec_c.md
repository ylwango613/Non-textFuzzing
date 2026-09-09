전체 분석 완료. 최종 결론을 기록합니다.

**분석 요약:**

1. **`expand_rle_row8` / `expand_rle_row16`**: 출력 버퍼 경계 검사 (`out_end - out_buf < count`) 존재. 입력 읽기는 `bytestream2_get_byte(g)` (safe, 데이터 없으면 0 반환) 사용. 안전.

2. **`read_rle_sgi`**: RLE 테이블 크기 사전 검증 (`len * 2 > bytestream2_get_bytes_left(g)`). `bytestream2_seek(SEEK_SET)` 은 오프셋을 `[0, buffer_size]` 범위로 클램핑. `start_offset`이 `unsigned int > INT_MAX`일 경우 음수로 형변환되지만, `av_clip(negative, 0, ...)` → 0으로 클램프되어 안전하게 처리됨. 안전.

3. **`read_uncompressed_sgi`**: `rowsize * (int64_t)height * nb_components` 사전 검증 후 `bytestream2_get_bufferu`(unsafe) 호출. 사전 검증이 전체 필요 바이트를 보장하므로 안전.

4. **정수 오버플로우**: width/height는 `be16u`로 읽혀 최대 65535. `height * nb_components * 4` 최대값은 65535×4×4 = 1,048,560으로 `unsigned int` 범위 내. 안전.

5. **`decode_frame`**: `ff_set_dimensions` / `ff_get_buffer` 가 차원 검증 및 버퍼 할당 처리. `nb_components` 검증 (1/3/4만 허용). 안전.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
