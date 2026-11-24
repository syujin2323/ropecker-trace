# 13주차 추가 검증 사례 (`cases/extra/`)

고정 사례 3종(`cases/frozen.json`)은 그대로 두고, 그 밖의 정상·위반·경계 입력을 여기에 **사례 하나 = 파일 하나**로 추가합니다.
기대와 다르게 동작한 입력(반례)은 실행기가 반례 목록(C1…)으로 모으고, 각자 분류(구현 버그 / 명세상 미지원 / 원논문 한계)를 적습니다.
계획과 담당은 이슈 #13, 13주차 규칙은 과제 자료 6~9쪽입니다.

## 순서

1. **사례 파일을 쓰고 PR로 먼저 올린다.** 입력과 기대 결과(`기대 결과`, `expect`)는 실행 **전에** 적습니다. 커밋 기록이 "실행 전에 적었다"는 근거가 됩니다.
2. **트레이스를 준비한다.**
   - 합성: `uv run python -m ropecker.synth --extra --only E7` → `traces/extra/<check id>.jsonl.gz`
   - 수집: `collect/`로 모아 `traces/real/` 등에 두고 check의 `trace`에 경로를 적습니다.
3. **실행한다.** `uv run python scripts/run_cases.py --cases cases/extra --only E7` → `results/w13/compare.md`(사례 표 + 반례 목록), `results/w13/runs/`(로그·결과 JSON)
4. **결과를 분석해 적는다.** 사례 파일에 `결과 분석`(분류·근거·처리)을 더합니다. `기대 결과`와 `expect`는 바꾸지 않습니다.
5. **구현 버그면 고친 뒤 같은 입력으로 다시 실행한다.** 고치기 전 결과는 `--out results/w13/E2-before-fix`처럼 따로 남겨 수정 전·후를 나란히 보입니다.

- 반례가 나오지 않아도 시험한 입력과 결과가 기록으로 남습니다(13주차 자료 6쪽 "반례 없음도 근거가 있으면 유의미").
- 합성 트레이스는 한 번 만들면 덮어쓰지 않습니다(`--force`를 줄 때만 다시 만듦). gadget DB를 고친 뒤에도 **같은 입력**으로 재실행하기 위해서입니다.
- 형식은 `uv run pytest`(tests/test_extra.py)가 CI에서 검사합니다. 사례 결과가 기대와 다른 것은 실패가 아닙니다.

## 파일 이름과 최상위 키

파일 이름: `E<번호>-<영문 소문자 짧은 이름>.json` (예: `E2-loop-filter.json`). 번호는 이슈 #13의 E 번호이고, 새 사례는 E13부터 씁니다. `examples/`(E90번대)는 형식 예시이며 기본 실행에는 들어가지 않습니다.

| 키 | 필수 | 내용 |
|---|---|---|
| `id` | ✅ | `"E7"` |
| `제목` | ✅ | 한 줄 제목 |
| `담당` | ✅ | 이름 |
| `작성일` | | `"2026-11-26"` |
| `방향` | ✅ | `경계값` · `표기 변형` · `반복·동시` · `자원 고갈` · `상태 전이` · `알려진 한계` (13주차 자료 7쪽) |
| `구분` | ✅ | `정상` · `위반` · `경계` |
| `입력` | ✅ | 무엇을 넣는지(사람이 읽는 설명) |
| `기대 결과` | ✅ | 실행 전에 적는 기대(사람이 읽는 설명). 공격 입력의 기대는 "탐지"입니다 |
| `근거` | | 기대의 근거(논문 절, design.md 등) |
| `params` | | 사례 전체의 `window`·`threshold`·`cmp` (기본은 고정 사례와 같은 W=8192, T=11, ge) |
| `checks` | ✅ | 실행할 항목 목록(아래) |
| `결과 분석` | | 실행 뒤 적음: `{"분류": "구현 버그", "근거": "…", "처리": "…"}` |

`분류` 값은 `구현 버그` · `명세상 미지원` · `원논문 한계` · `반례 아님` 중 하나입니다(13주차 자료 9쪽).

- **구현 버그:** 의도한 명세대로 동작하지 않음 → 고친 뒤 같은 입력으로 재실행
- **명세상 미지원:** 우리가 다루지 않기로 한 입력 → 한계로 기록, 필요하면 보완 방법 메모
- **원논문 한계:** 원래 방어도 막지 못함 → 원논문의 해당 절과 함께 기록
- 구분이 어려우면 원논문이 같은 상황을 다루는지 먼저 확인하고 판단 근거를 적습니다.
- 원논문 절: Ⅱ-B LBR, Ⅴ-C 실행 시 탐지(과거·미래 연쇄, jmp gadget 에뮬레이션), Ⅶ-A 임계값, Ⅶ-B gadget 길이(긴 gadget 끼워 넣기), Ⅶ-C 윈도 크기, Ⅸ-A 스택 피벗, Ⅸ-B gadget 접합, Ⅸ-C 짧은 연쇄, Ⅸ-D 윈도 안 gadget

## check 세 가지

check마다 `id`(영문 소문자·숫자·`-`, 사례 전체에서 겹치지 않게)와 `expect`가 있습니다.

```jsonc
// 1) 수집한 트레이스
{"id": "e1-real-boundary-11", "trace": "traces/real/f3-boundary-11.jsonl.gz",
 "expect": {"verdict": "ROP", "chain_len": 11}}

// 2) 합성 트레이스(스펙은 아래). 트레이스 경로는 traces/extra/<check id>.jsonl.gz
{"id": "e7-long-gadget", "synth": {"chain": [{"pick": {"asm": "^ret$"}}, {"nongadget": {"n_min": 7}}], "ending": "execve"},
 "expect": {"verdict": "ROP"}}

// 3) 단위 테스트(gadget DB 계산처럼 트레이스가 아닌 것). cases/extra/ 아래 pytest 테스트 하나
{"id": "e3-popcnt", "pytest": "cases/extra/unit/test_e3_db.py::test_popcnt_is_not_pop", "expect": {"pass": true}}
```

트레이스 check에는 `params`(이 check만 다른 W·T·비교 방식)와 `args`(CLI 옵션 추가, 예: `["--align-check"]`, `["--lbr-depth", "8"]`)를 더할 수 있습니다. `--trace`·`--json`·`--window`·`--threshold`·`--cmp`·`--no-check`·`--verbose`는 실행기가 붙이므로 `args`에 쓰지 않습니다.
단위 테스트는 기본 `uv run pytest`(tests/만 수집)에 들어가지 않으므로, 버그를 재현하는 실패 테스트를 두어도 CI가 깨지지 않습니다.

### `expect` 키 (판정은 고정 사례와 같은 `ropecker.cases.judge`)

| 키 | 뜻 |
|---|---|
| `verdict` (필수) | `"정상"` 또는 `"ROP"` |
| `chain_len` / `chain_len_min` / `chain_len_max` | 연쇄 길이 = / ≥ / ≤ (ROP면 처음 ROP가 나온 체크포인트, 정상이면 최댓값) |
| `past_len` / `future_len` | 그 체크포인트의 과거·미래 연쇄 |
| `detect_step_max` | 이 스텝 이하에서 ROP로 탐지(스텝은 0부터) |
| `gadgets_nonempty` | 연쇄를 이룬 gadget 주소 출력 |
| `trace_end` | 트레이스 끝, 예: `"exit:0"`, `"syscall:59"`, `"max_steps"` |

단위 check의 `expect`는 `{"pass": true}`(통과해야 함) 또는 `{"pass": false}`입니다.

## 합성 트레이스 스펙 (`synth`)

고정 사례 합성 트레이스와 같이 rop_vault `vuln` 끝(`nop; leave; ret`)에서 시작해, `chain`의 항목을 차례로 실행한 트레이스를 만듭니다. 주소는 모두 rop_vault·sysroot libc의 실제 명령이고, 체인 스택(공격 페이로드)은 처음부터 깔려 있습니다.

```jsonc
"synth": {
  "chain": [
    {"pick": {"asm": "^pop rdi; ret$"}, "pops": ["0x404060"]},   // gadget DB에서 고르기
    {"addr": "libc.so.6+0x29659"},                                  // 주소 지정("rop_vault+0x…", "0x…"도 됨)
    {"nongadget": {"n_min": 7}},                                    // gadget이 아닌 긴 조각(명령 7개 이상, 끝은 ret)
    {"pick": {"asm": "^ret$", "module": "rop_vault"}, "page": "same"}
  ],
  "ending": "execve",       // execve(기본) | stop | none
  "stack_qwords": 32        // 스냅샷 크기(수집기와 같은 32가 기본, 1~512)
}
```

- **항목 하나에 `pick` · `addr` · `nongadget` 중 하나**
  - `pick` 조건(모두 선택): `asm`(gadget 명령 문자열 정규식, 예 `"^ret$"`, `"loop"`), `kind`(`ret`·`jmp_ind`·`call_ind`), `aligned`(true/false), `n`·`n_min`·`n_max`(명령 수), `sd_known`(rsp 변화를 아는지), `module`(`libc.so.6` 기본, `rop_vault`), `index`(조건에 맞는 것 중 몇 번째, 기본 0). 주소 순으로 찾으므로 결과가 항상 같습니다.
  - `nongadget`: `n_min`(기본 7)·`n_max`(기본 12)·`module`·`index`. DB의 6개짜리 ret gadget 앞에 평범한 명령을 붙여 만든 조각이라 정의상 gadget이 아닙니다(논문 Ⅶ-B의 긴 gadget).
- **`page`** (`pick`·`nongadget`만): `new`(기본, 아직 안 쓴 코드 페이지 → 진입마다 체크포인트), `same`(바로 앞 항목과 같은 페이지, 첫 항목이면 vuln의 rop_vault 페이지), `any`. `new`·`same`은 조각이 한 페이지 안에 있는 것만 고릅니다.
- **`pops`:** 항목 안의 `pop`이 꺼낼 값 목록(순서대로, 모자라면 0).
- **`rsp_to`:** rsp를 정적으로 알 수 없는 명령(`pop rsp`, `leave`, `xchg rsp, …` 등)을 지난 뒤의 rsp. 스택 피벗을 만들 때 씁니다. 없으면 만들 때 오류로 알려 줍니다.
- **`sys`:** 항목 안에 `syscall`이 있으면 그 번호(예: `syscall; ret` gadget으로 execve면 59).
- **따라가는 규칙:** 항목은 간접 분기(ret·jmp*·call*)를 만날 때까지 실행합니다.
  - `ret`은 다음 항목 주소를 스택에서 꺼냅니다(`ret imm16`은 그만큼 더 건너뜀).
  - `jmp*`·`call*`의 목적지는 레지스터에 있어 트레이스에 없으므로 '다음 항목 주소'로 둡니다(`call*`은 복귀 주소를 스택에 쌓음).
  - 직접 `jmp`는 따라가고(gadget 접합, Ⅸ-B), 조건 분기(jcc·loop 계열)는 '뛰지 않음'으로 봅니다.
  - `retf`, 직접 `call`, 명령 32개 안에 간접 분기가 없는 조각은 오류입니다.
- **`ending`:**
  - `execve`: 마지막 항목이 libc의 syscall 지점(gadget 아님)으로 가서 execve(59)를 부르고 끝납니다(고정 사례 위반과 같음).
  - `stop`: gadget이 아닌 지점에 닿고 끝납니다(경계 사례와 같음).
  - `none`: 착지 스텝 없이 마지막 항목의 분기에서 끝납니다(새 페이지 진입이 없어 체크포인트도 생기지 않음).
- 만든 트레이스 헤더에는 `spec`과 실제로 쓰인 항목(`entries`: 주소, 고른 방식, gadget 여부, 실행한 명령)이 남습니다.

## 예시

`examples/E90-ret-chain-boundary.json`(pick, ending stop, 경계 11·10), `examples/E91-addr-pops-unit.json`(addr·pops, 과거 연쇄 기대값, 단위 테스트 check).

```bash
uv run python -m ropecker.synth --extra --cases cases/extra/examples      # 예시 트레이스(이미 있으면 건너뜀)
uv run python scripts/run_cases.py --cases cases/extra/examples --out results/examples.tmp   # 커밋하지 않는 폴더
```
