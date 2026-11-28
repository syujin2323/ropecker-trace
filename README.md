# ropecker-trace

**ROPecker(NDSS 2014)의 gadget 연쇄 탐지를 실행 트레이스 기반 사용자 공간 명령행 도구로 재현**하는 소프트웨어및시스템보안(2026-2) 논문 구현 프로젝트입니다. 실행 트레이스를 입력받아 체크포인트마다 과거 + 미래 gadget 연쇄를 세고, 임계값 이상이면 ROP로 판정해 연쇄 길이와 gadget 주소를 출력합니다.

- 논문: Cheng et al., *ROPecker: A Generic and Practical Approach for Defending Against ROP Attacks*, NDSS 2014 ([PDF](https://www.ndss-symposium.org/wp-content/uploads/2017/09/02_1_1.pdf))
- 팀: 6조 — 송유진(팀장, 기반·CLI·비교 실행기), 심형섭(과거 연쇄·통합 판정), 김종훈(gadget DB), 안세진(트레이스 수집), 김수영(윈도·미래 연쇄)
- 저장소: https://github.com/syujin2323/ropecker-trace (이 문서의 상대 경로와 링크는 저장소 루트 기준입니다)
- 원 논문은 커널 모듈과 CPU의 LBR을 쓰지만, 이 저장소는 **실행 트레이스(명령어 주소 시퀀스)**를 입력받아 같은 판정 로직(과거 연쇄 + 미래 연쇄 ≥ T)을 재현합니다. 정의·형식·원논문과의 차이는 [docs/design.md](docs/design.md)에 있습니다.

## 실행 환경

| 항목 | 버전·내용 |
|---|---|
| 분석·테스트 OS | macOS 27 (Apple Silicon, arm64), Windows 11·10 (PowerShell), Ubuntu (GitHub Actions) — CI가 세 OS에서 모두 실행, 팀원 재실행 기록은 `results/w12/repro.md` |
| Python | 3.11 (`.python-version`, uv가 자동 설치. 개발 기준 3.11.15, 재실행·CI에서 3.11.0·3.11.9·3.11.18도 확인) |
| 패키지 관리 | [uv](https://docs.astral.sh/uv/) (0.11.28·0.12.22·0.13.9에서 확인), 버전 고정은 `uv.lock` |
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
uv run pytest    # 157 passed, 2 skipped (실제로 수집하지 않은 경계 트레이스 2개는 skip)
```

- Windows PowerShell에서 한글이 깨지면 먼저 `$env:PYTHONUTF8 = "1"`을 실행합니다(CI도 같은 설정).

## 한 줄 실행

```bash
# 보호 적용 후: 체크포인트마다 gadget 연쇄를 세어 판정 (종료 코드 0 정상, 1 ROP, 2 오류·미구현)
uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11

# 보호 적용 전: 탐지 없이 실행 요약만 (위반 트레이스는 execve(59)에 도달 = 셸 실행)
uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11 --no-check
```

- `.venv`를 활성화했다면 `uv run` 없이 `python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11`처럼 실행해도 됩니다(11주차 보고서 명령의 `t.log` 자리에 트레이스 경로를 넣습니다).
- 결과 JSON 저장은 `--json result.json`, 체크포인트별 방어자 판정 로그 출력은 `--verbose`, 논문 기준(연쇄 > T) 비교는 `--cmp gt`
- 합성 트레이스 4개(`traces/synth/`)는 11주차 동결 사례의 기준 입력입니다. `uv run python -m ropecker.synth`로 언제든 같은 파일이 다시 만들어집니다. 실제 수집 트레이스(`traces/real/`, 정상·위반)도 `--trace traces/real/f2-violation.jsonl.gz`처럼 경로만 바꿔 같은 명령으로 판정합니다.

보호 적용 후 명령의 화면 출력은 아래와 같고 종료 코드는 1입니다. `--no-check`를 붙이면 `판정: 미검사 (--no-check, 보호 적용 전)`과 마지막 줄만 나오고 종료 코드는 0입니다.

```text
판정: ROP (연쇄 길이 17 = 과거 1 + 미래 16, 기준 연쇄 ≥ 11)
체크포인트: 스텝 3, pc 0x7ffff7da9659, 이유 window
  gadget 0x7ffff7da9659 (libc.so.6+0x29659, past)
  gadget 0x7ffff7daa179 (libc.so.6+0x2a179, future)
  … (future gadget 15줄 더)
실행 스텝 24, 트레이스 종료 syscall:59
```

## 검증 사례

11주차 보고서(11/16 재제출본) 4.5의 정상·위반·경계 사례입니다. 문구와 기대 결과는 `cases/frozen.json`에 그대로 두고, `tests/test_frozen.py`가 해시로 잠가 바꾸지 않습니다. 모호했던 판정 기준을 코드·출력값으로 정한 내용은 `docs/design.md` 2절에 있습니다.

| 구분 | 입력 | 기대 결과 | 트레이스 (check id) |
|---|---|---|---|
| 정상 | 6주차 실습 바이너리를 버퍼 크기 미만의 평범한 문자열로 실행한 트레이스 | 미탐지. 판정 "정상", 연쇄 길이 10 이하(T=11 미만), 프로그램 정상 종료 | `f1-normal` (합성·실제 수집) |
| 위반 | 같은 바이너리에서 gadget 17개가 연달아 이어지는 ROP 실행 트레이스 | 탐지. 연쇄 길이가 임계값 11 이상이므로 판정 "ROP", 연쇄를 이룬 gadget 주소 출력 | `f2-violation` (합성·실제 수집) |
| 경계 | 연쇄 길이가 임계값과 정확히 같은 11인 체인, 그리고 10인 체인 | 기준이 "T 이상"이므로 11은 "ROP", 10은 "정상". 한 칸 차이로 판정이 갈리는지 확인 | `f3-boundary-11`, `f3-boundary-10` (합성) |

트레이스 파일은 `traces/synth/<check id>.jsonl.gz`(합성, 정답 포함)와 `traces/real/<check id>.jsonl.gz`(실제 수집)입니다.

## 보호 적용 전·후 비교

```bash
uv run python scripts/run_cases.py
```

- 동결 사례의 트레이스 6개(합성 4개 + 실제 수집 2개)를 보호 적용 전(`--no-check`)과 후(기본 실행 + `--verbose`)로 같은 조건(W=8192, T=11)에서 한 번씩 실행합니다.
- 결과는 `results/w12/compare.md`(비교표)와 `results/w12/runs/`(콘솔 로그·결과 JSON)에 남습니다. 표의 '일치'는 `uv run pytest`의 동결 사례 테스트와 같은 기준입니다.
- 현재 결과는 아래 표와 같습니다(적용 후 판정 일치 6 · 불일치 0 · 미구현 0 · 오류 0). 담당 모듈이 아직 stub(`NotImplementedError`)이면 '적용 후' 열에 "미구현"이 나옵니다.

| 구분 | 트레이스 | 보호 적용 전 (`--no-check`) | 보호 적용 후 (탐지) | 기대와 일치 |
|---|---|---|---|---|
| 정상 | 합성 `f1-normal` | 8스텝, 끝 exit:0 | 정상, 연쇄 0 | 일치 |
| 정상 | 실제 `f1-normal` | 9,368스텝, 끝 exit:0 | 정상, 최대 연쇄 1 | 일치 |
| 위반 | 합성 `f2-violation` | 24스텝, 끝 syscall:59 (execve 호출) | ROP, 연쇄 17, 스텝 3에서 중단 | 일치 |
| 위반 | 실제 `f2-violation` | 8,443스텝, 끝 syscall:59 (execve 호출 지점까지 제어 흐름 탈취) | ROP, 연쇄 18, 스텝 8422에서 중단 (execve는 스텝 8442) | 일치 |
| 경계 | 합성 `f3-boundary-11` | 18스텝, 끝 max_steps | ROP, 연쇄 11, 스텝 3에서 중단 | 일치 |
| 경계 | 합성 `f3-boundary-10` | 17스텝, 끝 max_steps | 정상, 연쇄 10 | 일치 |

- 스텝 번호는 0부터 셉니다. '중단'은 탐지기가 ROP로 판정하고 분석을 멈춘 스텝입니다(원논문은 이때 프로세스를 끝냅니다).
- `max_steps`는 합성 경계 트레이스가 체인 뒤 gadget이 아닌 지점에서 기록을 마쳤다는 뜻입니다(종료·syscall 없음).
- 실제 위반 트레이스는 수집기가 execve 스텝을 기록한 직후 대상을 끝낸 기록이라 셸이 실제로 뜨지는 않았습니다(`traces/real/f2-violation.stdout.txt`의 `Terminated via GDBstub`).
- 실제 위반의 연쇄 18은 페이로드 gadget 17개에, `read`가 복귀한 `vuln` 끝 `nop; leave; ret`(0x4012a5)이 gadget 시작 주소라 과거 연쇄에 하나 더 들어간 값입니다.

## 추가 검증 사례 (13주차)

고정 사례 3종은 그대로 두고, 정상·위반·경계 입력을 `cases/extra/`에 사례 하나 = 파일 하나로 더해 반례를 찾습니다. 기대 결과는 실행 전에 적고, 기대와 다른 결과는 반례 목록(C1…)으로 모아 구현 버그·명세상 미지원·원논문 한계로 분류합니다. 형식과 작성 순서는 [cases/extra/README.md](cases/extra/README.md), 계획과 담당은 이슈 #13에 있습니다.

```bash
uv run python -m ropecker.synth --extra --only E7                   # 합성 스펙 → traces/extra/ (이미 있는 트레이스는 건너뜀)
uv run python scripts/run_cases.py --cases cases/extra --only E7    # 자기 사례만 → results/w13-only.tmp/ (커밋 안 함)
uv run python scripts/run_cases.py --cases cases/extra              # 전체 → results/w13/compare.md(사례 표 + 반례 목록), results/w13/runs/
```

## 원논문과의 차이

- 커널 모듈·page fault·CPU의 LBR 대신 기록된 실행 트레이스를 사용자 공간에서 분석합니다. LBR은 트레이스의 최근 간접 분기 16개로 흉내 냅니다(§II-B).
- 판정은 11주차 보고서대로 연쇄 ≥ T(기본 T=11)입니다. 논문은 T 초과("exceeds")이며 `--cmp gt`로 논문 기준 판정도 볼 수 있습니다.
- 미래 연쇄는 ret gadget만 따라갑니다. jmp·call gadget과 rsp 변화를 알 수 없는 gadget(`leave` 등)에서 멈추며, 논문의 jmp 에뮬레이션(§V-C)은 13주차에 다룹니다.
- 윈도는 최근 실행한 코드 페이지 W/4096개(LRU, 기본 W=8192)입니다. 크기는 논문 실험값(8KB·16KB)을 따르고 교체 정책은 우리 선택입니다.
- 대상은 x86-64(논문은 x86-32)라 스택 변위가 8바이트 단위이고, 대상 실행은 qemu-user에서 합니다. 정의는 `docs/design.md`에 있습니다.

## 진행 현황

| 모듈 | 레인(라벨) | 상태 | 목표 |
|---|---|---|---|
| `model.py` 계약, `trace.py` 입출력, `cli.py` | infra | ✅ M0 | — |
| `image.py` 모듈 적재·명령 분류 | infra | ✅ M0 | — |
| `synth.py` 합성 트레이스 4개(동결 사례 기준) | infra | ✅ M0 | — |
| `target/` 빌드·sysroot | infra | ✅ M0 | — |
| `collect/` 수집 이미지·`gdb_trace.py` | collect | ✅ 정상·위반 입력 실제 트레이스(재수집 시 같은 파일) | W12 (11/23) |
| `gadgetdb.py` gadget DB (`python -m ropecker.gadgetdb` → `data/gadgets/` 3개) | db | ✅ scan·build·save·GadgetDB · ✅ ROPgadget 교차검증 `compare_ropgadget`(E4) · loop 계열 필터·rsp 변화 계산 수정(E2·E3) | W12 (W13) |
| `lbr.py`·`past.py` 과거 연쇄 (최근 16개, ret 우선) | past | ✅ | W12 |
| `window.py`·`future.py` 윈도·미래 연쇄 (ret만) | future | ✅ LRU 윈도·위험 syscall 체크포인트·ret 미래 연쇄 · ⬜ jmp gadget 에뮬레이션 | W12 (W13) |
| `detector.py` 통합 판정 | past·infra | ✅ (모든 레인 연결, 결과 `stubs` 빈 목록) | W12 |
| `scripts/run_cases.py` 보호 적용 전·후 비교표, CLI 판정 로그(`--verbose`) | infra | ✅ 적용 전·후 비교표(적용 후 판정 일치 6 · 미구현 0)·판정 로그 | W12 |
| `cases/extra`·`extra.py` 추가 사례 형식·검사, `synth.py --extra` 합성 스펙, `run_cases.py --cases` 실행·반례 목록 | infra | ✅ | W13 (11/24) |
| 추가 사례 E1~E12 실행·반례 분류 | all | ⏳ E2~E4·E6~E8 실행·분류(수정 뒤 반례 5, 고친 구현 버그 2) · ⬜ E1·E5·E9~E12 (이슈 #13) | W13 (11/30) |
| `experiments/` 14주차 실험(주 T=5~17, 보조 W) | any | ✅ 계획 초안(`experiments/README.md`, 11/29 확정) · ⬜ `sweep.py` | W14 |

레인별 계약 예시 테스트(`tests/test_<모듈>.py`)는 미구현이면 xfail로 표시되고, 구현이 들어오면 저절로 pass/fail로 바뀝니다. 모든 레인이 구현되어 xfail은 없습니다(11/28 기준 `uv run pytest`: 157 passed, 2 skipped — 실제 수집하지 않은 경계 트레이스 2개, 13주차 E1에서 수집 예정). 추가 사례 형식 검사는 `tests/test_extra.py`가 합니다.

## 저장소 구조

```
ropecker/        분석기(순수 Python) — model.py가 레인 사이의 계약, cases.py가 동결 사례 판정 기준
tests/           pytest — test_frozen.py가 11주차 동결 사례 실행
cases/           frozen.json(11주차 동결 3사례, 해시로 잠금), extra/(13주차 추가 사례, 형식은 extra/README.md)
traces/          synth/(합성, 정답 포함) real/(실제 수집) extra/(13주차 추가 사례 합성)
data/gadgets/    모듈별 gadget DB
target/          대상 바이너리 소스·빌드 스크립트·바이너리·sysroot
collect/         x86 실행·트레이스 수집(Docker)
experiments/     14주차 실험 계획·결과(T·W)
scripts/         run_cases.py(보호 적용 전·후 비교표, --cases로 13주차 추가 사례)
results/         w12/(동결 사례 비교표·로그), w13/(추가 사례 표·반례 목록·로그)
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

x86-64 대상 실행은 `collect/`의 Docker 이미지 안에서만 합니다(qemu-user gdbstub + gdb Python API). 수집한 트레이스는 커밋하므로, Docker가 없어도 분석과 테스트는 모두 할 수 있습니다. 자세한 내용은 [collect/README.md](collect/README.md)에 있습니다. 같은 입력이면 누가 수집해도 같은 파일이 나오므로, 다시 수집한 뒤 `git status`에 `traces/real/` 변경이 없으면 재현된 것입니다(정상 입력은 맥 OrbStack·Windows Docker Desktop, 위반 입력은 Windows에서 확인. 기록: `collect/README.md` '재현성', `results/w12/repro.md`).

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

## 참고 자료

- 원논문: Cheng et al., *ROPecker: A Generic and Practical Approach for Defending Against ROP Attacks*, NDSS 2014 (맨 위 '논문' 항목의 PDF)
- 참고한 코드·라이브러리: capstone 5.0.9(디스어셈블), pyelftools 0.33(ELF 읽기), ROPgadget 7.7(gadget 교차 검증), qemu-user·gdb-multiarch(트레이스 수집), pytest·ruff(검증), uv(환경 고정). 대상 프로그램은 위 '출처'의 6주차 실습 코드입니다.
- AI 활용: Claude (Anthropic) Opus 5.5(안세진은 Opus 4.8)의 도움을 받아 설계·구현·문서 작업을 했습니다. 사람·날짜별 요청 내용, 확인 방법, 채택·수정한 부분, 어려웠던 점은 [docs/ai-log.md](docs/ai-log.md)에 기록합니다.
