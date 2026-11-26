# 추가 검증 사례 실행 결과 (13주차)

> `uv run python scripts/run_cases.py --cases cases/extra`가 만든 파일입니다. 직접 고치지 말고 다시 실행하세요.

- 실행: 2026-11-27 00:58 +0900, Windows-10-10.0.26200-SP0, Python 3.11.15
- 기본 파라미터: W=8192, T=11, 판정 연쇄 ≥ T (사례마다 다른 조건은 '트레이스·조건' 열)
- 보호 적용 전: `--no-check`, 보호 적용 후: 기본 실행 + `--verbose`. 기대 결과는 사례 파일에 실행 전에 적은 값이다.
- 결과: 기대와 같음 1 · 기대와 다름(반례) 7 · 실행 전 0 · 오류 0
- 일부만 실행: E3 (`--only`)

## 추가 검증 사례

| 사례 | 방향 | 구분 | 트레이스·조건 | 보호 적용 전 | 보호 적용 후 | 기대 결과 | 결과 | 증거 |
|---|---|---|---|---|---|---|---|---|
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_popcnt_is_not_pop` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-popcnt.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_16bit_push_pop_is_2_bytes` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-16bit.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_64bit_push_pop_unchanged` | — | 테스트 통과 | 테스트 통과 | ✅ 기대와 같음 | [로그](runs/e3-64bit-same.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_enter_level0_moves_rsp_by_8_plus_size` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-enter.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_enter_nested_is_unknown` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-enter-nested.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_sixteen_bit_pop_sp_is_pivot` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-pop-sp.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_iret_sysret_are_unknown` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-iret.pytest.log) |
| E3 gadget DB의 rsp 변화(sd·adv) 계산 — popcnt·16비트 push/pop·enter·iret | 표기 변형 | 정상 | 단위 테스트 `cases/extra/unit/test_e3_rsp_delta.py::test_16bit_ret_is_unknown` | — | 테스트 실패 | 테스트 통과 | ❌ 기대와 다름: 테스트 실패 (기대 통과) | [로그](runs/e3-ret16.pytest.log) |

## 반례 목록

| 번호 | 입력 | 기대 결과 | 실제 결과 | 분류 | 처리 | 판단 근거 |
|---|---|---|---|---|---|---|
| C1 | E3 `e3-popcnt`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C2 | E3 `e3-16bit`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C3 | E3 `e3-enter`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C4 | E3 `e3-enter-nested`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C5 | E3 `e3-pop-sp`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C6 | E3 `e3-iret`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |
| C7 | E3 `e3-ret16`: rsp를 건드리는 명령 뒤에 ret이 붙은 바이트열(popcnt, push ax·pop ax·pushfw·popfw·push imm16·push fs, enter n,0과 n,1, pop sp, iretq·sysretq, 16비트 ret)을 DB 생성기에 넣어 sd·adv를 본다. 정상 코드의 명령 해석이므로 구분은 '정상' | popcnt는 rsp 불변(sd 0·adv 8), 16비트 push/pop은 ±2바이트, 64비트 push fs는 8바이트, enter n,0은 8+n바이트 내림, 그 밖의 중첩 enter·pop sp·iretq·sysretq·16비트 ret은 정적으로 모르므로 None(논문 Table II need emulation) | 테스트 실패 — 테스트 실패 (기대 통과) | 분류 전 | — | — |

- 분류·처리·판단 근거는 사례 파일의 "결과 분석"에 적은 값이다(13주차 자료 9쪽: 구현 버그 / 명세상 미지원 / 원논문 한계). 비어 있으면 "분류 전".
- 기대와 다른 결과는 기대값을 바꾸지 않고 원인 분석으로 잇는다. 구현 버그를 고치면 같은 입력으로 다시 실행해 전·후를 남긴다.
