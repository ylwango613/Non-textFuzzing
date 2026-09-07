분석이 완료되었습니다. 두 가지 확인된 취약점을 찾았습니다:

**발견 요약:**
1. `Ap4HvccAtom.cpp:255` — `payload_size < 22` 조건이 `payload_size == 22`일 때 `payload[22]` OOB 읽기를 허용 (off-by-one)
2. `Ap4AvccAtom.cpp:88` — seq params 루프 후 `cursor == payload_size`일 때 `payload[cursor]` OOB 읽기

두 취약점 모두 공격자가 제어하는 MP4 파일의 hvcC/avcC atom 크기로 트리거됩니다.

## VULN: Heap OOB Read in AP4_HvccAtom ctor via off-by-one size check
- **漏洞类别**: memory-safety
- **函数**: AP4_HvccAtom::AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload)
- **行号**: 255-282 (Ap4HvccAtom.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_HvccAtom::Create(size_32, stream) → AP4_HvccAtom::AP4_HvccAtom(size, payload) [Ap4HvccAtom.cpp:282: payload[22] OOB read]
- **描述**: `AP4_HvccAtom::AP4_HvccAtom(AP4_UI32 size, const AP4_UI08* payload)` 중 line 255의 바운드 체크가 `if (payload_size < 22) return;`로 되어 있어, `payload_size == 22`일 때 조건을 통과한다. 이후 line 282에서 `AP4_UI08 num_seq = payload[22];`를 실행하면, `payload_data`는 정확히 22바이트(인덱스 0-21)만 할당되어 있어 `payload[22]`가 힙 버퍼 1바이트 밖을 읽는 out-of-bounds read가 발생한다. 올바른 조건은 `if (payload_size < 23) return;`이어야 한다.
- **触发条件**: 공격자는 MP4 파일에 hvcC(또는 hvce) atom의 total size 필드를 정확히 30바이트(`AP4_ATOM_HEADER_SIZE`(8) + 22 = 30`)로 설정한다. `payload_size = 30 - 8 = 22`가 되어 off-by-one 체크를 통과하고 OOB read가 발생한다.
- **安全影响**: 힙 adjacent 영역의 1바이트 유출(heap layout 정보 노출)로 ASLR 우회 또는 추가 익스플로잇 체인의 정보 수집에 활용 가능. 인접 메모리가 매핑 외 영역일 경우 SIGSEGV/process crash(DoS)가 발생한다. `num_seq`가 OOB 바이트 값(최대 255)으로 설정되어 `m_Sequences.SetItemCount(255)`가 호출될 수 있어 대규모 메모리 할당을 유발한다.

## VULN: Heap OOB Read in AP4_AvccAtom::Create when cursor reaches payload end
- **漏洞类别**: memory-safety
- **函数**: AP4_AvccAtom::Create(AP4_Size size, AP4_ByteStream& stream)
- **行号**: 88 (Ap4AvccAtom.cpp)
- **CWE**: CWE-125 (Out-of-bounds Read)
- **CVSS v3.1**: 7.1 (AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:H)
- **严重程度**: High
- **攻击向量**: crafted MP4 file
- **外部触发路径**: mp42aac main() → AP4_File(stream) → AP4_AtomFactory::CreateAtomFromStream() → AP4_AvccAtom::Create(size_32, stream) [Ap4AvccAtom.cpp:88: payload[cursor] OOB read when cursor == payload_size]
- **描述**: `AP4_AvccAtom::Create()`에서 sequence parameters 루프 종료 후, `cursor`가 `payload_size`와 같아질 수 있다. 이 때 line 88의 `unsigned int num_pic_params = payload[cursor++];`가 `payload[payload_size]`를 읽어 `AP4_DataBuffer payload_data(payload_size)`로 할당된 힙 버퍼의 1바이트 밖을 읽는 OOB read가 발생한다. 함수는 직후 `if (cursor > payload_size) return NULL;`로 NULL을 반환하지만 OOB read는 이미 완료된 상태이다.
- **触发条件**: 공격자는 avcC(또는 avce) atom을 다음 두 방법 중 하나로 구성한다: (1) `payload_size == 6`이고 `num_seq_params = payload[5] & 31 == 0`으로 설정하면(atom total size = 14바이트), seq params 루프를 전혀 실행하지 않아 cursor=6=payload_size가 되고 `payload[6]` OOB가 발생한다. (2) sequence parameters의 길이 합계가 정확히 `payload_size - 6`바이트가 되도록 설정하면 루프 종료 후 cursor=payload_size가 된다.
- **安全影响**: 힙 버퍼 1바이트 밖 읽기로 인한 인접 힙 메타데이터 또는 할당 데이터 유출(정보 노출), 혹은 매핑되지 않은 메모리 접근 시 process crash(DoS). 반환값은 NULL이라 파서가 atom을 무시하지만, 1바이트 OOB read 자체가 메모리 안전성 위반이다.

<!-- AUDIT_PROMPT_VERSION: 1 -->
