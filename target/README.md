# 대상 프로그램: rop_vault

- `src/rop_vault.c`, `src/Makefile`은 과목 실습 저장소 [RAKKUNN/SSS-2026-CTF](https://github.com/RAKKUNN/SSS-2026-CTF)의 6주차 ROP 실습 원본입니다(수정하지 않음).
- 보호 기법: NX 켜짐, 카나리 없음, no-PIE, ASLR 켜짐. 64바이트 버퍼에 256바이트를 `read` 합니다.

## 빌드 (M0 2일차에 `build.sh` 추가 예정)

`ubuntu:22.04`(amd64) 컨테이너에서 `make`로 컴파일하고, 같은 이미지의 `ld-linux-x86-64.so.2`와 `libc.so.6`(glibc 2.35)을 `sysroot/`로 꺼냅니다. 결과물의 해시는 `SHA256SUMS`에 기록하고, 트레이스·gadget DB 헤더의 sha256과 대조합니다.

```
target/
├── src/        과목 원본
├── build.sh    (예정)
├── bin/rop_vault
├── sysroot/lib64/ld-linux-x86-64.so.2
├── sysroot/lib/x86_64-linux-gnu/libc.so.6
└── SHA256SUMS
```
