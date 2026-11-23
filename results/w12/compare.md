# 보호 적용 전·후 비교 (12주차)

> `uv run python scripts/run_cases.py`가 만든 파일입니다. 직접 고치지 말고 다시 실행하세요.

- 실행: 2026-11-23 18:12 +0900, macOS-27.2.1-arm64-arm-64bit, Python 3.11.15
- 동결 사례 파라미터: W=8192, T=11, 판정 연쇄 ≥ T
- 보호 적용 전: `--no-check`(탐지 없이 실행 요약), 보호 적용 후: 기본 실행(탐지) + `--verbose`(판정 로그)
- 적용 후 판정: 일치 6 · 불일치 0 · 미구현 0 · 오류 0

| 사례 | 트레이스 | 보호 적용 전 (실행 결과) | 보호 적용 후 (방어자 판정) | 기대 결과 (동결) | 일치 | 증거 |
|---|---|---|---|---|---|---|
| 정상 | 합성 `f1-normal` | 8스텝, 끝 exit:0 (정상 종료) | 정상, 연쇄 0 | 정상, 연쇄 ≤ 10, 끝 exit:0 | ✅ 일치 | [전](runs/f1-normal-synth.before.log) · [후](runs/f1-normal-synth.after.log) |
| 정상 | 실제 수집 `f1-normal` | 9,368스텝, 끝 exit:0 (정상 종료) | 정상, 연쇄 1 | 정상, 연쇄 ≤ 10, 끝 exit:0 | ✅ 일치 | [전](runs/f1-normal-real.before.log) · [후](runs/f1-normal-real.after.log) · [프로그램 출력](../../traces/real/f1-normal.stdout.txt) |
| 위반 | 합성 `f2-violation` | 24스텝, 끝 syscall:59 (execve 도달 = 셸 실행) | ROP, 연쇄 17, 스텝 3에서 중단 (execve 전, 피해 제거) | ROP, 연쇄 ≥ 11, gadget 주소 출력 | ✅ 일치 | [전](runs/f2-violation-synth.before.log) · [후](runs/f2-violation-synth.after.log) |
| 위반 | 실제 수집 `f2-violation` | 8,443스텝, 끝 syscall:59 (execve 도달 = 셸 실행) | ROP, 연쇄 18, 스텝 8422에서 중단 (execve 전, 피해 제거) | ROP, 연쇄 ≥ 11, gadget 주소 출력 | ✅ 일치 | [전](runs/f2-violation-real.before.log) · [후](runs/f2-violation-real.after.log) · [프로그램 출력](../../traces/real/f2-violation.stdout.txt) |
| 경계 | 합성 `f3-boundary-11` | 18스텝, 끝 max_steps | ROP, 연쇄 11, 스텝 3에서 중단 | ROP, 연쇄 = 11 | ✅ 일치 | [전](runs/f3-boundary-11-synth.before.log) · [후](runs/f3-boundary-11-synth.after.log) |
| 경계 | 합성 `f3-boundary-10` | 17스텝, 끝 max_steps | 정상, 연쇄 10 | 정상, 연쇄 = 10 | ✅ 일치 | [전](runs/f3-boundary-10-synth.before.log) · [후](runs/f3-boundary-10-synth.after.log) |

- **보호 적용 전**은 탐지 없이 트레이스가 어떻게 끝났는지(공격자가 본 결과)이고, **보호 적용 후**는 방어자의 판정이다. 체크포인트별 판정 로그는 `runs/*.after.log`와 `runs/*.after.json`의 `checks`에 있다.
- **미구현**은 그 레인이 아직 stub이라 판정하지 못한 경우다(12주차 지침상 허용, 사유는 보고서에 적는다).
