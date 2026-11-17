#!/usr/bin/env bash
# 대상 프로그램 rop_vault를 과목 실습과 같은 환경(ubuntu:22.04, amd64, gcc 11)에서 빌드하고,
# 같은 이미지의 ld.so·libc(glibc 2.35)를 sysroot로 꺼낸다. 결과 해시는 SHA256SUMS에 기록한다.
#
#   bash target/build.sh          # 저장소 루트 어디서든 실행 가능
#
# 컴파일만 하므로 Apple Silicon(Rosetta)·Windows(Docker Desktop)에서도 그대로 된다.
set -euo pipefail
cd "$(dirname "$0")"

# 이미지 digest를 고정해 언제 빌드해도 같은 libc·ld.so를 쓴다.
IMAGE="ubuntu:22.04@sha256:9abcaffc92a5279fff3a6a41635c0800ea33e528425fb389658806476e7defde"

docker run --rm --platform linux/amd64 \
  -e HOST_UID="$(id -u)" -e HOST_GID="$(id -g)" \
  -v "$PWD":/t -w /t "$IMAGE" bash -euo pipefail -c '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends gcc make libc6-dev >/dev/null
    gcc --version | head -1 > bin.gcc-version.tmp
    make -s -C src clean rop_vault
    mkdir -p bin sysroot/lib64 sysroot/lib/x86_64-linux-gnu
    mv src/rop_vault bin/rop_vault
    cp -L /lib64/ld-linux-x86-64.so.2 sysroot/lib64/ld-linux-x86-64.so.2
    cp -L /lib/x86_64-linux-gnu/libc.so.6 sysroot/lib/x86_64-linux-gnu/libc.so.6
    dpkg-query -W -f="libc6 \${Version}\n" libc6 >> bin.gcc-version.tmp
    chown -R "$HOST_UID:$HOST_GID" bin sysroot bin.gcc-version.tmp
  '

{
  echo "# 빌드 환경: $IMAGE"
  sed 's/^/# /' bin.gcc-version.tmp
  shasum -a 256 bin/rop_vault sysroot/lib64/ld-linux-x86-64.so.2 sysroot/lib/x86_64-linux-gnu/libc.so.6
} > SHA256SUMS
rm -f bin.gcc-version.tmp
cat SHA256SUMS
