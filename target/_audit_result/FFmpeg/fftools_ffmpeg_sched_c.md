전체 파일 분석 완료. 검토 결과를 정리합니다.

**분석 요약:**

- **배치 1 (L1–500)**: 구조체 정의, waiter/task 초기화. 명시적 취약점 없음.
- **배치 2 (L500–999)**: `sch_add_*` 함수들, `GROW_ARRAY` 패턴. `grow_array`는 `INT_MAX / elem_size` 오버플로 체크 보유. 안전.
- **배치 3 (L999–1498)**: `sch_connect`, 스케줄링 로직. `unchoke_downstream`의 NULL 포인터 경로는 `start_prepare`에서 사전 검증됨.
- **배치 4 (L1498–1997)**: `mux_queue_packet`: `size_t pkt_size = pkt->size`에서 signed→unsigned 변환 주목. 오버플로가 `data_size` 논리를 왜곡할 수 있으나 할당 크기에 직접 영향 없음.
- **배치 5 (L1997–2496)**: `sch_demux_send` line 2196: `pkt->stream_index < d->nb_streams` signed/unsigned 혼합 비교. 음수 값은 unsigned 변환 후 `d->nb_streams`보다 크게 되어 assert 실패(abort) — 메모리 오염 없음.
- **배치 6 (L2496–2834)**: `task_wrapper`, `sch_stop` 등 스레드 종료 로직. 취약점 없음.

**핵심 결론**: `ffmpeg_sched.c`는 순수 스케줄링 레이어로서 외부 파일에서 직접 데이터를 읽거나 파싱하지 않습니다. 다루는 데이터는 demuxer/decoder가 이미 처리한 `AVPacket`/`AVFrame` 객체들이며, 크기 연산에서 직접적 heap allocation에 영향을 미치는 경로가 없습니다. 발견된 패턴들(signed/unsigned 혼합, `data_size` 오버플로)은 메모리 오염으로 이어지지 않습니다.

NO_VULN_FOUND

<!-- AUDIT_PROMPT_VERSION: 1 -->
