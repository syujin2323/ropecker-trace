# 트레이스 수집 (레인: collect)

x86-64 대상(rop_vault) 실행은 이 폴더의 Docker 이미지 안에서만 합니다. 수집한 트레이스는 `traces/real/`에 커밋하므로, Docker가 없어도 분석·테스트는 할 수 있습니다.

## 사용법

```bash
docker build -t rc-collect collect/
# macOS (저장소 루트에서)
docker run --rm -v "$PWD":/w -w /w rc-collect bash collect/run.sh f1-normal
```
```powershell
# Windows (PowerShell, Docker Desktop WSL2 백엔드)
docker run --rm -v "${PWD}:/w" -w /w rc-collect bash collect/run.sh f1-normal
```

- 입력: `collect/inputs/<이름>.txt`를 표준 입력으로 줍니다. 대상 인자는 `main`(6주차 Main 서비스와 같은 모드)입니다.
- 출력
  - `traces/real/<이름>.jsonl.gz`: 트레이스 v1(방어자가 보는 실행 기록)
  - `traces/real/<이름>.stdout.txt`: 프로그램 출력(공격자가 보는 결과)
- 최대 스텝은 두 번째 인자로 줍니다(기본 200000). 예: `bash collect/run.sh f1-normal 5000`

## 수집한 트레이스

| 이름 | 입력 | 스텝 | 끝 | 비고 |
|---|---|---|---|---|
| f1-normal | `hello` | 9,368 (rop_vault 157, ld.so 4,519, libc 4,692) | exit 0 | syscall: write 9회, read, exit_group. 간접 분기 235개 |
| f2-violation | ROP 페이로드(72B 패딩+체인) | 8,443 | syscall: 59 (execve) | 위반 사례. syscall write·read 후 execve 도달. buf→RET 72B, ret 슬레드 14+pop rdi/rsi/rax. `make_f2_violation.py --scan`으로 생성 |

## 동작 방식

1. `env -i qemu-x86_64 -seed 1 -L target/sysroot -g <포트>`로 대상을 띄웁니다.
   - 대상 ld.so·libc는 glibc 2.35입니다. Debian 크로스 libc(2.36)는 쓰지 않습니다.
   - 포트가 열릴 때까지 `/proc/net/tcp*`를 보고 기다립니다(접속 시도는 하지 않음).
2. `gdb-multiarch -x collect/gdb_trace.py`가 gdbstub에 붙어 `*main`까지 실행합니다.
3. **라이브러리 로드 주소**는 gdb의 공유 라이브러리 추적이 qemu 대상에서 동작하지 않아서, rop_vault의 `DT_DEBUG → r_debug.r_map → link_map`을 메모리에서 직접 따라가 `l_addr`로 구합니다.
4. 한 명령씩 `stepi`하며 모든 스텝에 pc를 기록하고, 실행 페이지가 바뀐 스텝과 syscall 스텝에는 `sp`·`stk`(32 qword) 스냅샷과 `sys`(rax)를 더합니다.
5. 종료·시그널은 gdb 이벤트(`exited`, `stop`)로 받아 마지막 행(`end`)에 적습니다.

## 재현성

같은 입력이면 누가 어디서 수집해도 **바이트 단위로 같은 파일**이 나옵니다. 다시 수집한 뒤 `git status`에 `traces/real/` 변경이 없으면 재현된 것입니다.

- `env -i`: 대상을 빈 환경 변수로 실행합니다.
  - 처음에는 컨테이너 이름·`RC_*` 같은 수집기 환경 변수가 qemu를 거쳐 대상 스택에 실렸습니다.
  - 그 길이에 따라 argv 문자열 주소가 바뀌었고, libc 문자열 비교 함수의 페이지 경계 검사(`and eax, 0xfff; cmp eax, 0xf80`) 결과도 달라졌습니다.
  - 그래서 main 진입 후 1,747스텝 뒤부터 pc 열이 갈라졌습니다(9,364 대 9,368 스텝).
- `-seed 1`: qemu가 실행마다 무작위로 채우던 AT_RANDOM을 고정합니다. 이 값에서 나오는 스택 카나리·포인터 가드가 스택 스냅샷에 나타납니다.
- gzip은 `mtime=0`으로 저장합니다. qemu·gdb·zlib 버전은 이미지 digest로 고정됩니다.
- 확인: 맥(OrbStack, arm64)과 Windows(Docker Desktop)에서 각각 두 번 수집해 sha256이 같았습니다. 위반 입력(f2-violation)도 Windows에서 두 번 수집해 `git status` 변경 없음(바이트 동일)을 확인했습니다. 상세는 `results/w12/repro.md`.

## 환경 메모

- `--platform`을 주지 않습니다. 맥(Apple Silicon)은 arm64, Windows·Linux는 amd64 네이티브 컨테이너로 떠서 같은 경로(qemu gdbstub)를 탑니다. 맥에서 amd64 컨테이너 안 gdb는 Rosetta가 ptrace를 지원하지 않아 쓰지 않습니다.
- 이미지: `debian:bookworm-slim`(digest 고정), qemu-user 7.2, gdb-multiarch 13.1(Python 3.11)
- qemu-user 안의 주소는 게스트 주소 공간입니다(예: libc 0x4000843000, ld.so 0x4000801000). 헤더의 `base`가 이 값이고, 분석기는 이를 기준으로 모듈을 올립니다.
