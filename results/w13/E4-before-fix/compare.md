# 추가 검증 사례 실행 결과 (13주차)

> `uv run python scripts/run_cases.py --cases cases/extra`가 만든 파일입니다. 직접 고치지 말고 다시 실행하세요.

- 실행: 2026-11-27 00:58 +0900, Windows-10-10.0.26200-SP0, Python 3.11.15
- 기본 파라미터: W=8192, T=11, 판정 연쇄 ≥ T (사례마다 다른 조건은 '트레이스·조건' 열)
- 보호 적용 전: `--no-check`, 보호 적용 후: 기본 실행 + `--verbose`. 기대 결과는 사례 파일에 실행 전에 적은 값이다.
- 결과: 기대와 같음 3 · 기대와 다름(반례) 1 · 실행 전 0 · 오류 0
- 일부만 실행: E4 (`--only`)

## 추가 검증 사례

| 사례 | 방향 | 구분 | 트레이스·조건 | 보호 적용 전 | 보호 적용 후 | 기대 결과 | 결과 | 증거 |
|---|---|---|---|---|---|---|---|---|
| E4 비정렬 gadget(명령 경계가 아닌 주소에서 시작)을 쓰는 연쇄와 ROPgadget 교차검증 | 표기 변형 | 위반 | 합성 `e4-unaligned-chain` | 16스텝, 끝 syscall:59 (execve 도달 = 셸 실행) | ROP, 연쇄 12, 스텝 3에서 중단 (execve 전, 피해 제거) | ROP, 연쇄 ≥ 11, gadget 주소 출력 | ✅ 기대와 같음 | [전](runs/e4-unaligned-chain.before.log) · [후](runs/e4-unaligned-chain.after.log) · [트레이스](../../../traces/extra/e4-unaligned-chain.jsonl.gz) |
| E4 비정렬 gadget(명령 경계가 아닌 주소에서 시작)을 쓰는 연쇄와 ROPgadget 교차검증 | 표기 변형 | 위반 | 합성 `e4-align-check` (`--align-check`) | 16스텝, 끝 syscall:59 (execve 도달 = 셸 실행) | ROP, 연쇄 1, 스텝 3에서 중단 (execve 전, 피해 제거) | ROP, gadget 주소 출력 | ✅ 기대와 같음 | [전](runs/e4-align-check.before.log) · [후](runs/e4-align-check.after.log) · [트레이스](../../../traces/extra/e4-align-check.jsonl.gz) |
| E4 비정렬 gadget(명령 경계가 아닌 주소에서 시작)을 쓰는 연쇄와 ROPgadget 교차검증 | 표기 변형 | 위반 | 단위 테스트 `cases/extra/unit/test_e4_unaligned.py::test_unaligned_gadget_is_in_db` | — | 테스트 통과 | 테스트 통과 | ✅ 기대와 같음 | [로그](runs/e4-unit-unaligned.pytest.log) |
| E4 비정렬 gadget(명령 경계가 아닌 주소에서 시작)을 쓰는 연쇄와 ROPgadget 교차검증 | 표기 변형 | 위반 | 단위 테스트 `cases/extra/unit/test_e4_unaligned.py::test_rop_vault_matches_ropgadget` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e4-ropgadget.pytest.log) |

## 반례 목록

| 번호 | 입력 | 기대 결과 | 실제 결과 | 분류 | 처리 | 판단 근거 |
|---|---|---|---|---|---|---|
| C1 | E4 `e4-ropgadget`: (1) libc의 비정렬 ret gadget 12개를 이은 합성 연쇄 + execve를, 기본 설정과 --align-check로 각각 실행한다. (2) 정렬 안 된 gadget을 일부러 만든 바이트열이 DB에 aligned=false로 들어가는지, (3) rop_vault 전체를 ROPgadget(--all)과 대조해 한쪽에만 있는 gadget이 있는지 본다 | (1) 둘 다 탐지(ROP). 기본 설정은 연쇄 길이 11 이상으로, --align-check는 비정렬 gadget을 만나는 즉시. (2) aligned=false로 기록. (3) 양쪽 주소 집합이 같다(ROPgadget의 직접 분기·6개 초과 조각은 대조에서 제외) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |

- 분류·처리·판단 근거는 사례 파일의 "결과 분석"에 적은 값이다(13주차 자료 9쪽: 구현 버그 / 명세상 미지원 / 원논문 한계). 비어 있으면 "분류 전".
- 기대와 다른 결과는 기대값을 바꾸지 않고 원인 분석으로 잇는다. 구현 버그를 고치면 같은 입력으로 다시 실행해 전·후를 남긴다.
