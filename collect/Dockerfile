# 트레이스 수집 이미지: x86-64 대상(rop_vault)을 qemu-user로 실행하고 gdb Python API로 한 명령씩 기록한다.
# --platform을 지정하지 않는다: 맥(Apple Silicon)은 arm64, Windows·Linux는 amd64 네이티브로 뜬다.
# (맥의 amd64 컨테이너 안 gdb는 Rosetta가 ptrace를 지원하지 않아 쓰지 않는다. gdbstub 방식은 ptrace가 필요 없다.)
# digest를 고정해 누가 빌드해도 같은 qemu·gdb 버전을 쓴다(멀티 아키텍처 인덱스라 arm64·amd64 모두 해당).
FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
RUN apt-get update \
 && apt-get install -y --no-install-recommends qemu-user gdb-multiarch python3 \
 && rm -rf /var/lib/apt/lists/*
WORKDIR /w
