# 설계: 정의와 데이터 형식 (단일 출처)

이 문서가 레인 사이의 약속입니다. 코드(`ropecker/model.py`)와 다르면 이 문서를 기준으로 맞추고, 바꿀 때는 둘을 같은 PR에서 고칩니다.

## 1. 용어 정의

| 용어 | 정의 | 논문 근거 |
|---|---|---|
| gadget | 직접 분기(jmp/jcc/call) 없이 간접 분기(ret, jmp*, call*)로 끝나는 명령 **6개 이하** 조각. 코드 섹션의 **모든 바이트 오프셋**에서 시작할 수 있다(비정렬 포함) | VI-A, VII-B |
| 과거 연쇄 | 간접 분기만 남긴 최근 **16개**(LBR 흉내)를 최신부터 거꾸로 보며, 분기의 목적지가 gadget인 동안 센 수 | V-C(2) |
| 미래 연쇄 | 체크포인트 스냅샷(sp, stk)에서 현재 pc의 ret gadget이 읽을 슬롯(sp+sd)의 주소를 따라가며, 그 주소가 gadget인 동안 센 수. jmp/call gadget이나 sd를 모르는 gadget에서 멈춘다 | V-C(3) |
| 판정 | 과거 + 미래 **≥ T**이면 ROP (`--cmp gt`면 논문처럼 > T). 처음 ROP가 나온 체크포인트에서 멈춘다 | VII-A |
| 윈도 | 최근에 실행한 코드 페이지 W/4096개(LRU). 윈도 밖 페이지의 명령을 실행하려는 순간이 체크포인트 | V-B |
| 위험 syscall | mmap(9), mprotect(10), mremap(25), execve(59)를 부르는 스텝도 체크포인트 | V-B(2) |
| 비정렬 검사 | `--align-check`를 켜면 비정렬 gadget을 만나는 즉시 ROP | Table II |

### 원 논문과의 차이 (14주차 final_report에서 정리)
- 커널 모듈·page fault·LBR 대신 **실행 트레이스**로 같은 판정을 재현한다.
- 판정 기준은 11주차 보고서대로 **≥ T**다. 논문은 "exceeds"(> T)다.
- 미래 연쇄에서 jmp 기반 gadget의 에뮬레이션은 생략한다(ret gadget만 따라간다).
- 윈도 교체 정책(LRU)과 크기는 논문 실험값(8KB/16KB)을 따르되 구현 세부는 우리 선택이다.
- 대상은 x86-64(논문은 x86-32), 실행 환경은 qemu-user다.

## 2. 트레이스 v1

JSON Lines(.jsonl, gzip 가능). 주소는 모두 `"0x..."` 문자열입니다.

```jsonc
// 1행: 헤더
{"fmt": "ropecker-trace", "v": 1, "collector": "gdb-qemu|qemu-exec|synth",
 "argv": ["rop_vault"], "stack_qwords": 32,
 "modules": [{"name": "rop_vault", "path": "target/bin/rop_vault", "sha256": "…", "base": "0x0"},
             {"name": "libc.so.6", "path": "target/sysroot/lib/x86_64-linux-gnu/libc.so.6", "sha256": "…", "base": "0x7f…"}],
 "truth": {"chain": ["0x…"]}}          // synth 전용: 정답 gadget 주소
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

## 3. gadget DB v1

`data/gadgets/<module>.gdb.jsonl.gz`

```jsonc
{"fmt": "ropecker-gadgetdb", "v": 1, "module": "libc.so.6", "sha256": "…", "max_insns": 6}
{"off": "0x2a3e5", "n": 2, "end": "0x2a3e6", "kind": "ret", "sd": 8, "adv": 16, "aligned": true, "asm": "pop rdi; ret"}
```

- `off`·`end`: ELF 가상주소. 런타임 주소 = base + off
- `sd`: gadget 시작 rsp → ret 슬롯 거리(바이트), `adv`: 실행 뒤 rsp 변화량. rsp를 예측할 수 없으면(leave, mov rsp 등) 둘 다 null

## 4. 결과 v1

화면 요약과 같은 내용을 `--json PATH`로 저장합니다. 키는 ASCII, 값의 판정은 한글입니다.

```jsonc
{"fmt": "ropecker-result", "v": 1,
 "verdict": "ROP",                      // 정상 | ROP | 미검사(--no-check)
 "chain_len": 17, "past_len": 2, "future_len": 15,   // 미탐지면 가장 긴 연쇄가 나온 체크포인트 값
 "gadgets": [{"addr": "0x…", "module": "libc.so.6", "off": "0x…", "from": "past|future"}],
 "checkpoint": {"step": 812, "pc": "0x…", "reason": "window|syscall:59"},
 "n_checkpoints": 41, "steps": 905, "trace_end": "exit:0",
 "params": {"window": 8192, "threshold": 11, "cmp": "ge", "lbr_depth": 16, "align_check": false, "check": true}}
```

종료 코드: 0 정상(또는 미검사), 1 ROP, 2 오류·미구현.

## 5. 동결 사례와 트레이스 파일

`cases/frozen.json`(11주차 4.5 문구 그대로)의 각 check id가 트레이스 파일 이름입니다.

| check id | 기대 | 기준 트레이스 |
|---|---|---|
| f1-normal | 정상, 연쇄 ≤ 10, exit:0 | traces/synth/f1-normal.jsonl.gz (+ real) |
| f2-violation | ROP, 연쇄 ≥ 11, gadget 주소 출력 | traces/synth/f2-violation.jsonl.gz (+ real) |
| f3-boundary-11 | ROP, 연쇄 = 11 | traces/synth/f3-boundary-11.jsonl.gz |
| f3-boundary-10 | 정상, 연쇄 = 10 | traces/synth/f3-boundary-10.jsonl.gz |

합성 트레이스는 rop_vault·libc의 실제 gadget 주소로 구성하고, 체인이 서로 다른 코드 페이지를 오가도록 배치해 체크포인트가 생기게 합니다. 실제 수집 트레이스가 기대와 다르면 **기대값은 고치지 않고** `cases/extra/`에 반례로 기록합니다(예상: 함수 끝 `leave; ret`이 gadget으로 세어짐, LBR 16개 한계, 한 윈도 안의 체인).

## 6. 실행 환경

- 분석: `uv`(Python 3.11). 모든 `open()`에 `encoding="utf-8"`(ruff PLW1514), 줄바꿈은 `.gitattributes`로 LF 고정.
- 대상: `ubuntu:22.04`(amd64)에서 `gcc -O0 -fno-stack-protector -no-pie -z noexecstack`로 빌드, 같은 이미지의 ld.so·libc(glibc 2.35)를 `target/sysroot`로 사용.
- 수집: `collect/` 이미지(debian bookworm + qemu-user + gdb-multiarch)에서 `qemu-x86_64 -L target/sysroot -g <port>`에 gdb Python API로 붙어 한 명령씩 실행. Debian 크로스 libc(2.36)는 쓰지 않습니다. bookworm의 QEMU 7.2는 `-singlestep` 옵션을 씁니다.
