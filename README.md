# ropecker-trace

**ROPecker(NDSS 2014)의 gadget 연쇄 탐지를 실행 트레이스 기반 사용자 공간 명령행 도구로 재현**하는 소프트웨어및시스템보안(2026-2) 논문 구현 프로젝트입니다. 6조: 송유진(팀장), 심형섭, 김종훈, 안세진, 김수영.

- 논문: Cheng et al., *ROPecker: A Generic and Practical Approach for Defending Against ROP Attacks*, NDSS 2014 ([PDF](https://www.ndss-symposium.org/wp-content/uploads/2017/09/02_1_1.pdf))
- 원 논문은 커널 모듈과 CPU의 LBR을 쓰지만, 이 저장소는 **실행 트레이스(명령어 주소 시퀀스)**를 입력받아 같은 판정 로직(과거 연쇄 + 미래 연쇄 ≥ T)을 재현합니다. 정의·형식·원논문과의 차이는 [docs/design.md](docs/design.md)에 있습니다.

## 실행 환경

| 항목 | 버전·내용 |
|---|---|
| 분석·테스트 OS | macOS 27 (Apple Silicon, arm64), Windows 11 (PowerShell), Ubuntu (GitHub Actions) — CI가 세 OS에서 모두 실행 |
| Python | 3.11 (`.python-version`, uv가 자동 설치. 개발 기준 3.11.15) |
| 패키지 관리 | [uv](https://docs.astral.sh/uv/) 0.12 이상, 버전 고정은 `uv.lock` |
| 의존성 | capstone 5.0.9, pyelftools 0.33 (개발: pytest 9.2.0, ruff 0.17.5, ROPgadget 7.7) |
| 대상 프로그램 | `target/bin/rop_vault` — 6주차 실습 소스, `ubuntu:22.04`(amd64) gcc 11.4.0, `-O0 -fno-stack-protector -no-pie -z noexecstack` |
| 대상 라이브러리 | `target/sysroot` — glibc 2.35-0ubuntu3.18 (빌드 이미지에서 추출, 해시는 `target/SHA256SUMS`) |
| 대상 빌드·트레이스 수집 | Docker (macOS는 OrbStack/Docker Desktop, Windows는 Docker Desktop WSL2). 분석·테스트에는 필요 없음 |
| 트레이스 수집 이미지 | `collect/Dockerfile` — debian bookworm-slim(digest 고정), qemu-user 7.2, gdb-multiarch 13.1 |

모든 경로는 저장소 루트 기준 상대 경로입니다.

## 빠른 시작

| | macOS | Windows (PowerShell) |
|---|---|---|
| uv 설치 | `brew install uv` | `winget install --id=astral-sh.uv -e` |

```bash
git clone https://github.com/syujin2323/ropecker-trace.git
cd ropecker-trace
uv sync          # Python 3.11 + capstone, pyelftools, pytest (uv.lock 그대로)
uv run pytest    # 미구현 레인은 xfail, 수집 전 실제 트레이스는 skip으로 표시됨
```

## 한 줄 실행

```bash
# 보호 적용 후: 체크포인트마다 gadget 연쇄를 세어 판정 (종료 코드 0 정상, 1 ROP, 2 오류·미구현)
uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11

# 보호 적용 전: 탐지 없이 실행 요약만 (위반 트레이스는 execve(59)에 도달 = 셸 실행)
uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11 --no-check
```

- `.venv`를 활성화했다면 보고서 문구 그대로 `python -m ropecker --trace t.log --window 8192 --threshold 11`도 됩니다.
- 결과 JSON 저장은 `--json result.json`, 논문 기준(연쇄 > T) 비교는 `--cmp gt`
- 합성 트레이스 4개(`traces/synth/`)는 11주차 동결 사례의 기준 입력입니다. `uv run python -m ropecker.synth`로 언제든 같은 파일이 다시 만들어집니다.

## 진행 현황

| 모듈 | 레인(라벨) | 상태 | 목표 |
|---|---|---|---|
| `model.py` 계약, `trace.py` 입출력, `cli.py` | infra | ✅ M0 | — |
| `image.py` 모듈 적재·명령 분류 | infra | ✅ M0 | — |
| `synth.py` 합성 트레이스 4개(동결 사례 기준) | infra | ✅ M0 | — |
| `target/` 빌드·sysroot | infra | ✅ M0 | — |
| `collect/` 수집 이미지·`gdb_trace.py` | collect | ✅ 정상 입력 실제 트레이스(재수집 시 같은 파일) · ⏳ 위반 입력 | W12 (11/23) |
| `gadgetdb.py` gadget DB | db | ⬜ | W12 |
| `lbr.py`·`past.py` 과거 연쇄 (최근 16개, ret 우선) | past | ⬜ | W12 |
| `window.py`·`future.py` 윈도·미래 연쇄 (ret만) | future | ⬜ | W12 |
| `detector.py` 통합 판정 | past·infra | ⬜ | W12 |
| `scripts/run_cases.py` 보호 적용 전·후 비교표 | infra | ⬜ | W12 |
| `experiments/sweep_t.py` T=5~17 실험 | any | ⬜ | W14 |

레인별 계약 예시 테스트(`tests/test_<모듈>.py`)는 지금은 xfail이고, 구현이 들어오면 저절로 pass/fail로 바뀝니다.

## 저장소 구조

```
ropecker/        분석기(순수 Python) — model.py가 레인 사이의 계약
tests/           pytest — test_frozen.py가 11주차 동결 사례 실행
cases/           frozen.json(11주차 동결 3사례, 해시로 잠금), extra/(13주차 추가·반례)
traces/          synth/(합성, 정답 포함) real/(실제 수집)
data/gadgets/    모듈별 gadget DB
target/          대상 바이너리 소스·빌드 스크립트·바이너리·sysroot
collect/         x86 실행·트레이스 수집(Docker)
experiments/     T 변화 실험
docs/            design.md(정의·형식), weekly/(주간보고서 원고), ai-log.md, final_report.md
```

## 함께 작업하는 방법

**main은 PR로만 바꿉니다.** 리뷰 승인은 필요 없고, **CI(ubuntu·macos·windows)가 통과하면 본인이 병합**합니다. 레인마다 파일이 나뉘어 있어 PR끼리 충돌할 일이 적습니다.

```bash
git switch main && git pull
git switch -c feat/<레인>-<주제>      # 예: feat/past-chain
# 작업
uv run pytest && uv run ruff check .
git push -u origin HEAD
gh pr create --fill                   # 또는 GitHub 웹에서 PR 생성
gh pr merge --auto --rebase           # CI 3 OS가 통과하면 자동 병합(나눈 커밋을 그대로 main에 반영)
```

- **CI가 빨간색이면:** PR의 "Details"에서 어느 OS의 어떤 테스트가 깨졌는지 보고, 고쳐서 같은 브랜치에 다시 push합니다.
- **계약 지키기:** 트레이스·DB·결과 형식을 바꾸면 `docs/design.md`와 `ropecker/model.py`를 같은 PR에서 고칩니다.
- **PR 템플릿:** 단위 입출력 확인(입력 → 출력)과 AI 활용 4칸을 채우면 그대로 주간보고서 재료가 됩니다.
- **주간보고서:** 각자 `docs/weekly/wNN.md`를 일요일까지 PR로 올리고, 팀장이 월요일에 PDF로 묶어 제출합니다.

## 트레이스 수집

x86-64 대상 실행은 `collect/`의 Docker 이미지 안에서만 합니다(qemu-user gdbstub + gdb Python API). 수집한 트레이스는 커밋하므로, Docker가 없어도 분석과 테스트는 모두 할 수 있습니다. 자세한 내용은 [collect/README.md](collect/README.md)에 있습니다. 같은 입력이면 누가 수집해도 같은 파일이 나오므로, 다시 수집한 뒤 `git status`에 `traces/real/` 변경이 없으면 재현된 것입니다(맥 OrbStack에서 확인, Windows는 W12 재현 확인 항목).

```bash
docker build -t rc-collect collect/
# macOS
docker run --rm -v "$PWD":/w -w /w rc-collect bash collect/run.sh f1-normal
```
```powershell
# Windows (PowerShell, Docker Desktop WSL2 백엔드)
docker run --rm -v "${PWD}:/w" -w /w rc-collect bash collect/run.sh f1-normal
```

## 출처

- 대상 프로그램 `target/src/rop_vault.c`, `Makefile`: 과목 실습 저장소 [RAKKUNN/SSS-2026-CTF](https://github.com/RAKKUNN/SSS-2026-CTF)의 6주차 ROP 실습(`전반부_2-7주차/week06_rop/05_rop/src`) 원본입니다. 다시 빌드한 바이너리의 주소(`pop rdi; ret` 0x4011de, `main` 0x4012a8 등)는 과목 원본 바이너리와 같습니다.
