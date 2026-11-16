# ropecker-trace

**ROPecker(NDSS 2014)의 gadget 연쇄 탐지를 실행 트레이스 기반 사용자 공간 명령행 도구로 재현**하는 소프트웨어및시스템보안(2026-2) 논문 구현 프로젝트입니다. 6조: 송유진(팀장), 심형섭, 김종훈, 안세진, 김수영.

- 논문: Cheng et al., *ROPecker: A Generic and Practical Approach for Defending Against ROP Attacks*, NDSS 2014 ([PDF](https://www.ndss-symposium.org/wp-content/uploads/2017/09/02_1_1.pdf))
- 원 논문은 커널 모듈과 CPU의 LBR을 쓰지만, 이 저장소는 **실행 트레이스(명령어 주소 시퀀스)**를 입력받아 같은 판정 로직(과거 연쇄 + 미래 연쇄 ≥ T)을 재현합니다. 정의와 형식은 [docs/design.md](docs/design.md)에 있습니다.

## 빠른 시작

[uv](https://docs.astral.sh/uv/)만 있으면 Python 3.11과 의존성을 자동으로 맞춥니다. 분석과 테스트는 macOS·Windows·Linux에서 같은 명령으로 돌아갑니다.

| | macOS | Windows (PowerShell) |
|---|---|---|
| uv 설치 | `brew install uv` | `winget install --id=astral-sh.uv -e` |

```bash
git clone https://github.com/syujin2323/ropecker-trace.git
cd ropecker-trace
uv sync          # Python 3.11 + capstone, pyelftools, pytest
uv run pytest    # 미구현 모듈은 xfail로 표시됨
```

## 한 줄 실행 (보고서 4.4)

```bash
# 보호 적용 후: gadget 연쇄를 세어 판정 (종료 코드 0 정상, 1 ROP, 2 오류)
uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11

# 보호 적용 전: 탐지 없이 실행 요약만
uv run python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 --threshold 11 --no-check
```

위 예시의 합성 트레이스(`traces/synth/`)는 M0 2일차(11/18)에 추가됩니다. 그 전에는 "트레이스를 읽지 못했습니다"가 나옵니다.

`.venv`를 활성화했다면 보고서 문구 그대로 `python -m ropecker --trace t.log --window 8192 --threshold 11`도 됩니다. 결과를 파일로 남기려면 `--json result.json`, 논문 기준(연쇄 > T)으로 비교하려면 `--cmp gt`를 붙입니다.

## 진행 현황

| 모듈 | 레인(라벨) | 상태 | 목표 |
|---|---|---|---|
| `model.py` 계약, `trace.py` 입출력, `cli.py` | infra | ✅ M0 | — |
| `image.py` 모듈 적재·명령 분류, `synth.py` 합성 트레이스 | infra | ⏳ M0 2일차 | 11/18 |
| `target/` 빌드·sysroot, `collect/` 수집 이미지 | infra·collect | ⏳ M0 2일차 | 11/18 |
| `gadgetdb.py` gadget DB | db | ⬜ | W12 (11/23) |
| `lbr.py`·`past.py` 과거 연쇄 | past | ⬜ | W12 |
| `window.py`·`future.py` 윈도·미래 연쇄 | future | ⬜ | W12 |
| `detector.py` 통합 판정 | past·infra | ⬜ | W12 |
| `experiments/sweep_t.py` T=5~17 실험 | any | ⬜ | W14 |

레인별 계약 예시 테스트(`tests/test_<모듈>.py`)는 지금은 xfail이고, 구현이 들어오면 저절로 pass/fail로 바뀝니다.

## 저장소 구조

```
ropecker/        분석기(순수 Python) — model.py가 레인 사이의 계약
tests/           pytest — test_frozen.py가 11주차 동결 사례 실행
cases/           frozen.json(11주차 동결 3사례, 해시로 잠금), extra/(13주차 추가·반례)
traces/          synth/(합성, 정답 포함) real/(실제 수집)
data/gadgets/    모듈별 gadget DB
target/          대상 바이너리 소스·빌드·sysroot
collect/         x86 실행·트레이스 수집(Docker)
experiments/     T 변화 실험
docs/            design.md(정의·형식), weekly/(주간보고서 원고), ai-log.md, final_report.md
```

## 함께 작업하는 방법

1. **이슈 고르기**: 레인 라벨(`db`, `past`, `future`, `collect`, `infra`, `docs`)과 주차 마일스톤(M0, W12, W13, W14)이 붙어 있습니다. 착수할 때 본인에게 assign하세요. 담당은 고정이 아니라 언제든 바꿀 수 있습니다.
2. **브랜치·PR**: `feat/<레인>-<주제>` 브랜치에서 작업하고 main으로 PR을 엽니다. 리뷰 1명은 권장이고, **CI(ubuntu·macos·windows 테스트)가 초록이어야 병합**합니다.
3. **계약 지키기**: 트레이스·DB·결과 형식을 바꾸면 `docs/design.md`와 `ropecker/model.py`를 같은 PR에서 고칩니다.
4. **AI 활용 기록**: PR 템플릿의 AI 4칸을 채우면 그대로 주간보고서 3번 재료가 됩니다.
5. **주간보고서**: 각자 `docs/weekly/wNN.md`에 금주 작업과 차주 계획을 일요일까지 쓰고, 팀장이 월요일에 PDF(2쪽, 팀당 1부)로 묶어 제출합니다.

## 트레이스 수집 (M0 2일차에 추가 예정)

x86-64 대상 실행은 `collect/`의 Docker 이미지 안에서만 합니다(qemu-user gdbstub + gdb Python API). 수집한 트레이스는 커밋하므로, Docker가 없어도 분석과 테스트는 모두 할 수 있습니다.

```bash
# macOS
docker run --rm -v "$PWD":/w -w /w rc-collect bash collect/run.sh normal
```
```powershell
# Windows (PowerShell, Docker Desktop WSL2 백엔드)
docker run --rm -v "${PWD}:/w" -w /w rc-collect bash collect/run.sh normal
```

## 출처

- 대상 프로그램 `target/src/rop_vault.c`, `Makefile`: 과목 실습 저장소 [RAKKUNN/SSS-2026-CTF](https://github.com/RAKKUNN/SSS-2026-CTF)의 6주차 ROP 실습(`전반부_2-7주차/week06_rop/05_rop/src`) 원본입니다.
