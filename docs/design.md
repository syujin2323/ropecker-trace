# 설계: 정의와 데이터 형식 (단일 출처)

이 문서가 레인 사이의 약속입니다. 코드(`ropecker/model.py`)와 다르면 이 문서를 기준으로 맞추고, 바꿀 때는 둘을 같은 PR에서 고칩니다.

## 1. 용어 정의

| 용어 | 정의 | 논문 근거 |
|---|---|---|
| gadget | 직접 분기(jmp/jcc/call) 없이 간접 분기(ret, jmp*, call*)로 끝나는 명령 **6개 이하** 조각. 코드 섹션의 **모든 바이트 오프셋**에서 시작할 수 있다(비정렬 포함) | VI-A, VII-B |
| 과거 연쇄 | 간접 분기만 남긴 **최근 16개**(LBR 크기)를 최신부터 거꾸로 보며, 분기의 목적지가 gadget인 동안 센 수. gadget이 아닌 목적지에서 멈춘다. 현재 pc의 gadget은 마지막 항목의 목적지로 여기에 들어간다 | II-B, V-C(2) |
| 미래 연쇄 | 체크포인트 스냅샷(sp, stk)에서 현재 gadget의 ret 슬롯(sp+sd)에 있는 주소를 따라가며, 그 주소가 gadget인 동안 센 수. **현재 gadget 다음부터** 센다. jmp/call gadget이나 sd를 모르는 gadget, 스냅샷 범위 밖에서 멈춘다 | V-C(3) |
| 체크포인트 연쇄 길이 | 과거 연쇄 길이 + 미래 연쇄 길이 | V-C |
| 판정 | 체크포인트 연쇄 길이 **≥ T**이면 ROP (`--cmp gt`면 논문처럼 > T). 처음 ROP가 나온 체크포인트에서 멈춘다(논문: 프로세스 종료) | VII-A |
| 윈도 | 최근에 실행한 코드 페이지 W/4096개(LRU). 윈도 밖 페이지의 명령을 실행하려는 순간이 체크포인트 | V-B |
| 위험 syscall | mmap(9), mprotect(10), mremap(25), execve(59)를 부르는 스텝도 체크포인트 | V-B(2) |
| 비정렬 검사 | `--align-check`를 켜면 비정렬 gadget을 만나는 즉시 ROP | Table II |

**12주차 우선순위(조교 코멘트 반영):** ret 연쇄(과거·미래)와 윈도부터 연결합니다. jmp 기반 gadget의 미래 연쇄는 13주차에 반례·원논문 차이로 다룹니다.

## 2. 판정 기준 구체화 (12주차 — 11주차 고정 사례 문구는 그대로)

12주차 지침("고정 사례 3종은 유지하되 모호한 판정 기준만 구체화")에 따라 코드·출력값 수준의 기준을 정합니다.

- **트레이스의 연쇄 길이(`chain_len`)**: ROP로 판정되면 처음 ROP가 나온 체크포인트의 체크포인트 연쇄 길이, 아니면 모든 체크포인트 중 최댓값
- **판정 출력**: `verdict`("정상"/"ROP"), 종료 코드(0/1), `gadgets`(연쇄를 이룬 gadget 주소, 과거 → 미래 순), `checkpoint`(step, pc, reason)
- **보호 적용 전 결과**: `--no-check` 실행 요약의 `trace_end`. 위반 사례는 `syscall:59`(execve 도달 = 셸 실행)
- **보호 적용 후 결과**: 판정과 멈춘 스텝. 위반 사례는 execve 스텝 *이전*에 ROP로 멈춰야 피해가 제거된 것

| 사례(check id) | 판정 기준 |
|---|---|
| 정상(f1-normal) | verdict = 정상, chain_len ≤ 10, trace_end = exit:0 |
| 위반(f2-violation) | verdict = ROP, chain_len ≥ 11, gadgets가 비어 있지 않음 |
| 경계(f3-boundary-11) | verdict = ROP, chain_len = 11 |
| 경계(f3-boundary-10) | verdict = 정상, chain_len = 10 |

### 원 논문과의 차이 (14주차 final_report에서 정리)
- 커널 모듈·page fault·LBR 대신 **실행 트레이스**로 같은 판정을 재현한다. LBR은 최근 16개 간접 분기로 흉내 낸다.
- 판정 기준은 11주차 보고서대로 **≥ T**다. 논문은 "exceeds"(> T)다.
- 미래 연쇄에서 jmp 기반 gadget의 에뮬레이션은 생략한다(ret gadget만 따라간다).
- 윈도 교체 정책(LRU)과 크기는 논문 실험값(8KB/16KB)을 따르되 구현 세부는 우리 선택이다.
- 대상은 x86-64(논문은 x86-32), 실행 환경은 qemu-user다.

## 3. 트레이스 v1

JSON Lines(.jsonl, gzip 가능). 주소는 모두 `"0x..."` 문자열입니다.

```jsonc
// 1행: 헤더
{"fmt": "ropecker-trace", "v": 1, "collector": "gdb-qemu|synth",
 "argv": ["rop_vault", "main"], "stack_qwords": 32,
 "modules": [{"name": "rop_vault", "path": "target/bin/rop_vault", "sha256": "…", "base": "0x0"},
             {"name": "libc.so.6", "path": "target/sysroot/lib/x86_64-linux-gnu/libc.so.6", "sha256": "…", "base": "0x…"}],
 "truth": {"chain": ["0x…"], "chain_len": 17}}   // synth 전용: 정답
// 스텝 행 (명령 하나를 실행하기 직전 상태, 행 순서 = 스텝 번호)
{"pc": "0x401196"}                                            // 모든 스텝
{"pc": "0x…", "sp": "0x…", "stk": ["0x…", …]}                 // 실행 페이지가 바뀐 스텝
{"pc": "0x…", "sp": "0x…", "stk": ["…"], "sys": 59}           // syscall 스텝(rax)
// 마지막 행
{"end": "exit", "code": 0}            // exit | signal(+signal) | syscall(+sys) | max_steps
```

- `base`는 로드 바이어스입니다(no-PIE 실행 파일은 0).
- 스냅샷(`sp`, `stk`)은 "실행 페이지가 바뀐 스텝과 syscall 스텝"에서만 찍습니다. 이 집합은 W가 얼마든 모든 체크포인트를 포함하므로 수집기는 W를 몰라도 됩니다.
- 분석기는 헤더의 `sha256`과 실제 파일이 다르면 거부합니다(libc 불일치 방지).
- gzip은 시각·파일 이름 없이(mtime=0) 써서 같은 내용이면 같은 바이트가 나옵니다.

## 4. gadget DB v1

`data/gadgets/<module>.gdb.jsonl.gz`

```jsonc
{"fmt": "ropecker-gadgetdb", "v": 1, "module": "libc.so.6", "sha256": "…", "max_insns": 6}
{"off": "0x2a3e5", "n": 2, "end": "0x2a3e6", "kind": "ret", "sd": 8, "adv": 16, "aligned": false, "asm": "pop rdi; ret"}
```

- 생성: `uv run python -m ropecker.gadgetdb` → rop_vault·libc.so.6·ld-linux-x86-64.so.2 세 개(실제 트레이스 헤더의 모듈 전부). 같은 입력이면 같은 바이트(gzip mtime=0). 분석할 때 DB가 없거나 헤더 sha256이 모듈 파일과 다르면 오류로 멈춘다(gadget을 0개로 세는 사고 방지)
- `off`·`end`: ELF 가상주소. 런타임 주소 = base + off
- `kind`: 끝 분기 종류 `ret` / `jmp_ind`(jmp reg·[mem]) / `call_ind`(call reg·[mem]). 논문의 ret-based / jmp-based 구분
- `aligned`: 실행 세그먼트 시작부터 선형 디스어셈블(objdump 방식, 디코드 실패는 1바이트 건너뜀)한 명령 경계인지. 논문도 정렬 정보는 선택 사항이며 부정확할 수 있다고 본다(VI-A)
- `sd`: gadget 시작 rsp → ret 슬롯 거리(바이트), `adv`: 실행 뒤 rsp 변화량. **ret gadget만** 계산하고 jmp/call gadget은 둘 다 null
  - 명령별 rsp 변화: push −8, pop +8, `add/sub rsp, imm` ±imm, `lea rsp, [rsp+disp]` +disp, rsp를 안 쓰는 명령 0
  - `sd` = ret 앞 명령들의 변화량 합, `adv` = `sd` + ret의 증가량(ret 8, `ret imm16`은 8+imm)
  - 예: `ret` (0, 8), `pop rdi; ret` (8, 16), `pop rdi; pop rsi; ret` (16, 24). x86-64라 논문(x86-32)의 4바이트 단위가 아니라 8바이트 단위
  - rsp를 예측할 수 없으면(leave, `pop rsp`, `mov/xchg rsp`, esp·sp에 쓰기, retf 등 스택 피벗) 둘 다 null. 논문 Table II의 "need emulation"에 해당하고, 미래 연쇄는 여기서 멈춘다

## 5. 결과 v1

화면 요약과 같은 내용을 `--json PATH`로 저장합니다. 키는 ASCII, 값의 판정은 한글입니다.

```jsonc
{"fmt": "ropecker-result", "v": 1,
 "verdict": "ROP",                      // 정상 | ROP | 미검사(--no-check)
 "chain_len": 17, "past_len": 1, "future_len": 16,
 "gadgets": [{"addr": "0x…", "module": "libc.so.6", "off": "0x…", "from": "past|future"}],
 "checkpoint": {"step": 3, "pc": "0x…", "reason": "window|syscall:59"},
 "checks": [{"step": 0, "pc": "0x…", "reason": "window", "past": 0, "future": 0, "total": 0},
            {"step": 3, "pc": "0x…", "reason": "window", "past": 1, "future": 16, "total": 17}],  // 방어자 판정 로그
 "n_checkpoints": 2, "steps": 24, "trace_end": "syscall:59",                         // 실행 결과(공격자 관점)
 "params": {"window": 8192, "threshold": 11, "cmp": "ge", "lbr_depth": 16, "align_check": false, "check": true},
 "stubs": []}                                                                            // 12주차 임시 구현을 쓴 함수
```

종료 코드: 0 정상(또는 미검사), 1 ROP, 2 오류·미구현.

- **`checks`(방어자 판정 로그):** 체크포인트마다 한 항목을 스텝 순서로 쌓는다.
  - 키는 `step`, `pc`, `reason`(`window` | `syscall:<번호>`), `past`, `future`, `total`(= past + future)이다.
  - ROP가 나오면 그 항목이 마지막이다(거기서 멈춘다).
  - `n_checkpoints`는 항목 수와 같고, `--no-check`이면 빈 목록이다.
- **요약 값:** `chain_len`·`past_len`·`future_len`·`checkpoint`는 `checks`의 한 항목에서 가져온다.
  - ROP면 마지막 항목, 정상이면 `total`이 가장 큰 항목(같으면 앞의 것)이다.
  - 체크포인트가 하나도 없으면 연쇄 값은 0, `checkpoint`는 null이다.
- **`stubs`(12주차 임시 구현):** 다른 레인이 아직 `NotImplementedError`이면 `detector.py`가 대체 동작으로 흐름을 잇고 그 함수 이름을 남긴다.
  - `window.checkpoints` → 같은 정의(LRU 페이지 W/4096개 + 위험 syscall)의 최소 구현, `future.future_chain` → 미래 연쇄 0(과거 연쇄만으로 판정)
  - 해당 레인이 구현되면 코드 수정 없이 빈 목록이 된다. 화면에는 "임시 구현(stub) 사용: …" 한 줄로 나온다.
- **로그 구분(12주차):** 실행 결과(공격자 관점)는 `steps`·`trace_end`, 방어자 판정은 `verdict`·`checks`다. 화면에는 `--verbose`(`-v`)일 때 판정 로그를 함께 출력한다.

## 6. 동결 사례와 트레이스 파일

`cases/frozen.json`(11주차 4.5 문구 그대로)의 각 check id가 트레이스 파일 이름입니다.

| check id | 기준 트레이스(합성) | 실제 수집 트레이스 |
|---|---|---|
| f1-normal | traces/synth/f1-normal.jsonl.gz | traces/real/f1-normal.jsonl.gz (W12 수집, 9,368스텝) |
| f2-violation | traces/synth/f2-violation.jsonl.gz | traces/real/f2-violation.jsonl.gz (W12 수집, 8,443스텝) |
| f3-boundary-11 | traces/synth/f3-boundary-11.jsonl.gz | — |
| f3-boundary-10 | traces/synth/f3-boundary-10.jsonl.gz | — |

**합성 트레이스(`ropecker/synth.py`)** 구성:
- 앞부분은 rop_vault `vuln`의 끝(nop; leave; ret)이다.
- 체인은 libc의 `ret`, `pop r; ret` gadget을 **모두 다른 코드 페이지**에서 골라 이어서, 체인의 각 gadget 진입이 체크포인트가 되게 한다.
- 위반 트레이스는 execve(59) syscall 스텝으로 끝난다. 경계 트레이스는 gadget이 아닌 지점에 착지해 끝난다. 정상 트레이스는 main → libc로 정상 복귀해 exit로 끝난다.
- 위 정의대로 계산하면 체인 안의 어느 체크포인트에서나 연쇄 길이가 정답(17/11/10)과 같다. 정상 트레이스는 0이다.

실제 수집 트레이스가 기대와 다르면 **기대값은 고치지 않고** `cases/extra/`에 반례로 기록하고 분류합니다(구현 버그 대 원논문 한계).

## 7. 실행 환경

- 분석: `uv`(Python 3.11). 모든 `open()`에 `encoding="utf-8"`(ruff PLW1514), 줄바꿈은 `.gitattributes`로 LF 고정.
- 대상: `ubuntu:22.04`(amd64, digest 고정)에서 gcc 11.4.0으로 빌드(`target/build.sh`). 같은 이미지의 ld.so·libc(glibc **2.35-0ubuntu3.18**)를 `target/sysroot`로 쓴다.
  - 과목이 6주차에 배포한 libc는 3.15라 libc 내부 오프셋은 다르다. 하지만 트레이스·gadget DB·수집이 모두 이 sysroot를 기준으로 하므로 서로 일관된다.
  - rop_vault 자체의 주소는 과목 원본과 같다.
- 수집: `collect/` 이미지(debian bookworm + qemu-user + gdb-multiarch)에서 `qemu-x86_64 -L target/sysroot -g <port>`에 gdb Python API로 붙어 `main`부터 한 명령씩 실행한다. Debian 크로스 libc(2.36)는 쓰지 않는다.
  - 대상은 빈 환경 변수(`env -i`)와 고정 시드(`qemu -seed 1`)로 실행한다. 환경 변수 길이가 argv 문자열 주소를 바꿔 libc 경로가 달라지고, AT_RANDOM이 스택 값을 바꾸기 때문이다. 그래서 같은 입력이면 같은 트레이스 파일이 나온다(`collect/README.md` "재현성").

## 8. 13주차 추가 검증 사례 (`cases/extra/`)

고정 사례는 그대로 두고, 추가 사례를 **사례 하나 = 파일 하나**(`cases/extra/E<번호>-<이름>.json`)로 둡니다. 작성 요령과 전체 문법은 [cases/extra/README.md](../cases/extra/README.md), 읽기·형식 검사는 `ropecker/extra.py`입니다.

- **기대 결과는 실행 전에** 적어 커밋합니다. 실행 뒤에는 `결과 분석`(분류·근거·처리)만 더하고 `기대 결과`·`expect`는 바꾸지 않습니다.
- check는 세 종류입니다: 수집한 트레이스(`trace`), 합성 트레이스(`synth` 스펙 → `traces/extra/<check id>.jsonl.gz`), 단위 테스트(`pytest`, `cases/extra/` 아래, 기본 `uv run pytest`에는 들어가지 않음).
- **`expect` 키:** 고정 사례의 `verdict`·`chain_len`·`chain_len_min`·`chain_len_max`·`gadgets_nonempty`·`trace_end`에 더해, 추가 사례에서만 쓰는 키가 셋 있습니다.
  - `past_len`·`future_len`: 판정한 체크포인트의 과거·미래 연쇄(결과 v1의 같은 이름 키)
  - `detect_step_max`: 이 스텝 이하에서 ROP로 탐지
  - 판정 함수는 고정 사례와 같은 `ropecker.cases.judge`입니다.
- **합성 트레이스 헤더:** `collector: "synth"`, `case`(check id), `spec`(사례 파일의 스펙 그대로), `entries`(실제로 쓰인 체인 항목: `addr`, `how` = pick·addr·nongadget, `gadget` 여부, 실행한 명령 `asm`)이 들어갑니다. 고정 사례 합성 트레이스와 달리 `truth`(정답)는 없습니다. 판정 기준은 사례 파일의 `expect`입니다.
  - 스냅샷 규칙은 수집기와 같습니다: 실행 페이지가 바뀐 스텝과 syscall 스텝에 `sp`·`stk`. `stk` 길이는 `stack_qwords`(기본 32, 수집기와 같음)입니다.
  - 스냅샷은 그 스텝 직전의 스택입니다. 공격 페이로드(ret·pop이 읽는 값)는 처음부터 보이고, 실행 중에 쓴 값(push, call*이 쌓는 복귀 주소, `[rsp+x]` 쓰기)은 그 뒤 스텝에만 보입니다. 같은 칸에 서로 다른 두 값이 필요한 스펙은 만들지 않고 오류로 알립니다.
  - rsp 변화는 gadget DB(`sd`·`adv`)와 따로 계산합니다(예: `popcnt`는 pop이 아님, `enter n, 0`은 n+8만큼 내림). DB 계산에 버그가 있어도 합성 트레이스는 실제 실행과 같게 만들어지므로 그 버그가 판정 차이로 드러납니다. 16비트 push/pop, 중첩 enter, 스택에 수백 바이트를 쓰는 명령은 지원하지 않습니다.
  - 넘친 vuln 버퍼의 'A'는 덮어쓸 수 있는 기본값이고, 목적지를 스택에서 읽는 `jmp*`·`call*`(`[rsp+x]`)은 그 칸에 다음 항목 주소를 깝니다. `retf`로 끝나는 gadget은 `pick`이 고르지 않습니다.
  - 한 번 만든 합성 트레이스는 `--only <번호> --force` 없이는 덮어쓰지 않습니다. 구현 버그를 고친 뒤에도 같은 입력으로 다시 실행하기 위해서입니다. 헤더의 `spec`이 사례 파일의 스펙과 다르면(스펙만 고치고 다시 만들지 않음) 합성 도구는 경고하고 실행기는 ⚠️로 표시합니다.
- **실행과 결과:** `uv run python scripts/run_cases.py --cases cases/extra` → `results/w13/compare.md`(사례 표, 기대와 다른 결과를 모은 반례 목록 C1…), `results/w13/runs/`(전·후 콘솔 로그와 결과 JSON, 단위 테스트 로그). 기대와 다른 결과는 실행 실패가 아니라 반례이므로 종료 코드에 넣지 않습니다. 종료 코드는 0 = 오류 없음, 1 = ⚠️ 오류(실행 오류·스펙과 다른 옛 트레이스·skip된 단위 테스트), 2 = 사례 파일 형식 오류·없는 사례 번호입니다. `--only`로 일부만 돌리면 기본 결과 폴더는 커밋하지 않는 `results/w13-only.tmp/`이고, `results/w13/`은 전체 실행으로만 갱신합니다.
