# 트레이스 수집 (레인: collect) — M0 2일차에 Dockerfile·run.sh 추가 예정

x86-64 대상 실행은 이 폴더의 Docker 이미지 안에서만 합니다.

- 이미지: `debian:bookworm-slim` + `qemu-user` + `gdb-multiarch`(Python 포함)
- 방식: `qemu-x86_64 -L target/sysroot -g <port> target/bin/rop_vault` 에 `gdb-multiarch -x collect/gdb_trace.py`로 붙어 한 명령씩 실행하고, 트레이스 v1(docs/design.md)로 기록
- `--platform`을 주지 않습니다. 맥(Apple Silicon)은 arm64, Windows·Linux는 amd64 네이티브로 떠서 같은 경로(qemu gdbstub)를 탑니다. 맥에서 amd64 컨테이너 안 gdb는 Rosetta가 ptrace를 지원하지 않아 동작하지 않습니다.
- Debian 크로스 libc(2.36)는 쓰지 않고 반드시 `-L target/sysroot`(glibc 2.35)를 씁니다.
- bookworm의 QEMU는 7.2라 한 명령 단위 실행 옵션이 `-singlestep`입니다(8.1부터 `-one-insn-per-tb`).

```bash
docker build -t rc-collect collect/
# macOS
docker run --rm -v "$PWD":/w -w /w rc-collect bash collect/run.sh normal
```
```powershell
# Windows (PowerShell)
docker run --rm -v "${PWD}:/w" -w /w rc-collect bash collect/run.sh normal
```
