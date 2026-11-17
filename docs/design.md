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
{"off": "0x2a3e5", "n": 2, "end": "0x2a3e6", "kind": "ret", "sd": 8, "adv": 16, "aligned": true, "asm": "pop rdi; ret"}
```

- `off`·`end`: ELF 가상주소. 런타임 주소 = base + off
- `sd`: gadget 시작 rsp → ret 슬롯 거리(바이트), `adv`: 실행 뒤 rsp 변화량. rsp를 예측할 수 없으면(leave, mov rsp 등) 둘 다 null

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
 "params": {"window": 8192, "threshold": 11, "cmp": "ge", "lbr_depth": 16, "align_check": false, "check": true}}
```

종료 코드: 0 정상(또는 미검사), 1 ROP, 2 오류·미구현.

- **`checks`(방어자 판정 로그):** 체크포인트마다 한 항목을 스텝 순서로 쌓는다.
  - 키는 `step`, `pc`, `reason`(`window` | `syscall:<번호>`), `past`, `future`, `total`(= past + future)이다.
  - ROP가 나오면 그 항목이 마지막이다(거기서 멈춘다).
  - `n_checkpoints`는 항목 수와 같고, `--no-check`이면 빈 목록이다.
- **요약 값:** `chain_len`·`past_len`·`future_len`·`checkpoint`는 `checks`의 한 항목에서 가져온다.
  - ROP면 마지막 항목, 정상이면 `total`이 가장 큰 항목(같으면 앞의 것)이다.
  - 체크포인트가 하나도 없으면 연쇄 값은 0, `checkpoint`는 null이다.
- **로그 구분(12주차):** 실행 결과(공격자 관점)는 `steps`·`trace_end`, 방어자 판정은 `verdict`·`checks`다. 화면에는 `--verbose`(`-v`)일 때 판정 로그를 함께 출력한다.

## 6. 동결 사례와 트레이스 파일

`cases/frozen.json`(11주차 4.5 문구 그대로)의 각 check id가 트레이스 파일 이름입니다.

| check id | 기준 트레이스(합성) | 실제 수집 트레이스 |
|---|---|---|
| f1-normal | traces/synth/f1-normal.jsonl.gz | traces/real/f1-normal.jsonl.gz (W12 수집, 9,368스텝) |
| f2-violation | traces/synth/f2-violation.jsonl.gz | traces/real/f2-violation.jsonl.gz (W12 시도) |
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
