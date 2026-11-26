# 추가 검증 사례 실행 결과 (13주차)

> `uv run python scripts/run_cases.py --cases cases/extra`가 만든 파일입니다. 직접 고치지 말고 다시 실행하세요.

- 실행: 2026-11-27 00:57 +0900, Windows-10-10.0.26200-SP0, Python 3.11.15
- 기본 파라미터: W=8192, T=11, 판정 연쇄 ≥ T (사례마다 다른 조건은 '트레이스·조건' 열)
- 보호 적용 전: `--no-check`, 보호 적용 후: 기본 실행 + `--verbose`. 기대 결과는 사례 파일에 실행 전에 적은 값이다.
- 결과: 기대와 같음 1 · 기대와 다름(반례) 2 · 실행 전 0 · 오류 0
- 일부만 실행: E2 (`--only`)

## 추가 검증 사례

| 사례 | 방향 | 구분 | 트레이스·조건 | 보호 적용 전 | 보호 적용 후 | 기대 결과 | 결과 | 증거 |
|---|---|---|---|---|---|---|---|---|
| E2 loop 계열(loop·loope·loopne)을 품은 조각이 gadget DB에 들어가는지 | 표기 변형 | 위반 | 단위 테스트 `cases/extra/unit/test_e2_loop_filter.py::test_loop_family_is_not_inside_gadget` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e2-unit-loop.pytest.log) |
| E2 loop 계열(loop·loope·loopne)을 품은 조각이 gadget DB에 들어가는지 | 표기 변형 | 위반 | 단위 테스트 `cases/extra/unit/test_e2_loop_filter.py::test_shipped_db_has_no_loop_gadget` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e2-unit-db.pytest.log) |
| E2 loop 계열(loop·loope·loopne)을 품은 조각이 gadget DB에 들어가는지 | 표기 변형 | 위반 | 합성 `e2-loop-chain` | 17스텝, 끝 syscall:59 (execve 도달 = 셸 실행) | ROP, 연쇄 12, 스텝 3에서 중단 (execve 전, 피해 제거) | ROP, 연쇄 ≥ 11, gadget 주소 출력 | ✅ 기대와 같음 | [전](runs/e2-loop-chain.before.log) · [후](runs/e2-loop-chain.after.log) · [트레이스](../../../traces/extra/e2-loop-chain.jsonl.gz) |

## 반례 목록

| 번호 | 입력 | 기대 결과 | 실제 결과 | 분류 | 처리 | 판단 근거 |
|---|---|---|---|---|---|---|
| C1 | E2 `e2-unit-loop`: (1) loop·loope·loopne·jrcxz 뒤에 ret이 붙은 바이트열을 DB 생성기(scan)에 넣고, 저장소 DB에 loop 계열 gadget이 있는지 센다. (2) libc의 `loopne X; ret` 조각 하나를 가운데(6번째)에 끼운 ret gadget 12개 연쇄 + execve를 합성 트레이스로 만들어 실행한다 | (1) loop 계열을 품은 조각은 gadget이 아니다(조건 분기, design.md 직접 분기 없음 규칙). jrcxz와 같은 군. 저장소 DB에도 없다. (2) 공격 입력이므로 탐지(ROP)를 기대한다 | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C2 | E2 `e2-unit-db`: (1) loop·loope·loopne·jrcxz 뒤에 ret이 붙은 바이트열을 DB 생성기(scan)에 넣고, 저장소 DB에 loop 계열 gadget이 있는지 센다. (2) libc의 `loopne X; ret` 조각 하나를 가운데(6번째)에 끼운 ret gadget 12개 연쇄 + execve를 합성 트레이스로 만들어 실행한다 | (1) loop 계열을 품은 조각은 gadget이 아니다(조건 분기, design.md 직접 분기 없음 규칙). jrcxz와 같은 군. 저장소 DB에도 없다. (2) 공격 입력이므로 탐지(ROP)를 기대한다 | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |

- 분류·처리·판단 근거는 사례 파일의 "결과 분석"에 적은 값이다(13주차 자료 9쪽: 구현 버그 / 명세상 미지원 / 원논문 한계). 비어 있으면 "분류 전".
- 기대와 다른 결과는 기대값을 바꾸지 않고 원인 분석으로 잇는다. 구현 버그를 고치면 같은 입력으로 다시 실행해 전·후를 남긴다.
