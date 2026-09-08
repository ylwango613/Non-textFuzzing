이제 전체 분석이 완료되었습니다.

**분석 요약:**

- `g722.c` (164줄): 순수 수학/계산 함수. 외부 입력 없이 고정 크기 정적 테이블만 사용. `s_zero()`, `do_adaptive_prediction()`, `linear_scale_factor()`, `ff_g722_update_low_predictor()`, `ff_g722_update_high_predictor()` 모두 av_malloc 없음, 배열 접근은 비트폭으로 자연 제한.
- `g722dec.c`: `frame->nb_samples = avpkt->size * 2` 곱셈 오버플로우 검토 → 오버플로우 시 결과는 항상 음수([INT_MIN, -2])로 `ff_get_buffer()`가 에러 반환. OOB write 불가. `prev_samples[]` 버스 접근은 홀짝성 불변조건(항상 짝수 위치) + 래핑 체크로 완전히 보호됨. 룩업 테이블 인덱스(`ilow`는 4~6비트 추출, `ihigh`는 2비트 추출)는 테이블 크기 이내.
- `g722enc.c`: 트렐리스 할당은 `av_calloc(frontier * FREEZE_INTERVAL, ...)` = `max_paths`로 정확히 bound됨. `av_assert2(pathn < max_paths)` 가드 존재.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
