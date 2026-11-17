#!/usr/bin/env bash
# 컨테이너 안에서(저장소 루트 /w) 실행한다:
#   bash collect/run.sh <입력 이름> [최대 스텝]
# 입력 collect/inputs/<이름>.txt 를 표준 입력으로 rop_vault를 qemu-user로 실행하고,
# gdb_trace.py가 한 명령씩 기록해 traces/real/<이름>.jsonl.gz 를 만든다.
# 프로그램 출력(공격자 관점)은 traces/real/<이름>.stdout.txt 에 따로 남긴다.
set -euo pipefail
NAME="${1:?사용법: bash collect/run.sh <입력 이름> [최대 스텝]}"
export RC_MAX="${2:-200000}"
export RC_PORT="${RC_PORT:-1234}"
export RC_OUT="${RC_OUT:-traces/real/${NAME}.jsonl.gz}"
export RC_ARGV="rop_vault main"
IN="collect/inputs/${NAME}.txt"
[ -f "$IN" ] || { echo "입력 파일 없음: $IN" >&2; exit 2; }
mkdir -p "$(dirname "$RC_OUT")"

# -L target/sysroot: 대상 ld.so·libc(glibc 2.35)를 쓴다. Debian 크로스 libc(2.36)는 쓰지 않는다.
# 누가 어디서 수집해도 같은 트레이스가 나오도록 대상의 시작 상태를 고정한다.
#   env -i : 빈 환경 변수. 컨테이너 이름·RC_* 값이 대상 스택에 실리면 argv 문자열 주소가 바뀌어
#            libc 문자열 함수의 경로(페이지 경계 검사)까지 달라진다.
#   -seed 1: AT_RANDOM(스택 카나리·포인터 가드)을 고정한다.
env -i qemu-x86_64 -seed 1 -L target/sysroot -g "$RC_PORT" target/bin/rop_vault main < "$IN" \
  > "${RC_OUT%.jsonl.gz}.stdout.txt" 2>&1 &
QPID=$!
trap 'kill "$QPID" 2>/dev/null || true' EXIT
# gdbstub 포트가 열릴 때까지 기다린다(접속해 보지 않고 /proc/net/tcp*의 LISTEN 상태만 확인)
PORT_HEX=$(printf '%04X' "$RC_PORT")
for _ in $(seq 1 100); do
  grep -qs ":${PORT_HEX} 0\{8,32\}:0000 0A" /proc/net/tcp /proc/net/tcp6 && break
  sleep 0.1
done
gdb-multiarch -q -nx -batch -x collect/gdb_trace.py
wait "$QPID" 2>/dev/null || true
