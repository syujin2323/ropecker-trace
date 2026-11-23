# W12 재현 확인 (collect 레인 · 안세진)

## 위반 입력(f2-violation) 결정적 수집

- 환경: Windows 11 + Docker Desktop (rc-collect 이미지, qemu-user + gdb-multiarch)
- 수집 명령: docker run --rm -v "${PWD}:/w" -w /w rc-collect bash collect/run.sh f2-violation
- 1차 수집 후 SHA256: A88566C39EA43B51FAEF95B99011E57E8F89EE404495164CAA2488B249CB3422
- 동일 입력 2차 수집 후 git status: nothing to commit, working tree clean
  → 두 번의 수집 결과가 바이트 단위로 동일(결정적 수집 확인)
- 트레이스: 8,443 스텝, 끝 행 {"end":"syscall","sys":59} (execve 도달)

## 결정적 수집의 근거
- env -i로 환경변수 제거, qemu -seed 1로 ASLR 고정
- 트레이스는 mtime=0으로 gzip 저장 → 압축 결과까지 재현

# W12 Windows 재실행 (체크리스트 9번 · 김종훈)

README "빠른 시작"대로 새로 clone한 main(`3a58243`)에서 실행했다.

- 환경: Windows 11 Pro (빌드 26200), PowerShell, uv 0.11.28, Python 3.11.15(uv가 `.python-version`대로 설치)
  - README는 uv 0.12 이상을 적고 있지만 0.11.28에서도 `uv sync --locked`가 그대로 됐다.
- 명령과 결과:

| 단계 | 명령 | 결과 |
|---|---|---|
| 설치 | `uv sync --locked` | 성공(capstone 5.0.9, pyelftools 0.33, pytest, ruff, ROPgadget) |
| 테스트 | `uv run pytest -q` | 34 passed, 2 skipped, 18 xfailed(미구현 레인), 실패 0 |
| 정적 검사 | `uv run ruff check .` | All checks passed |
| 보호 적용 전 | `uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11 --no-check` | 판정 미검사, 24스텝, 끝 `syscall:59`, 종료 코드 0 (README 설명과 같음) |
| 보호 적용 후 | 같은 명령에서 `--no-check` 뺌 | `미구현: gadgetdb.GadgetDB.open`, 종료 코드 2 (main에 gadget DB가 아직 없음, 예상대로) |
| 비교표 | `uv run python scripts/run_cases.py` | 종료 코드 0. `results/w12/runs/` 로그·JSON 18개는 커밋본(macOS)과 바이트 동일, `compare.md`는 실행 시각·플랫폼 줄만 다름 |

- 결론: Windows에서도 clone → 설치 → 테스트 → README 명령이 macOS와 같은 결과를 냈다.
- 참고(gadget DB PR #8 브랜치): 같은 PC에서 38 passed, 2 skipped, 16 xfailed이고, 보호 적용 후 실행은 `GadgetDB.open`을 지나 `미구현: detector.detect`(통합 레인)에서 멈춘다.
- 콘솔에 한글이 깨지면 `$env:PYTHONUTF8 = "1"`을 먼저 실행한다(CI도 같은 설정).
