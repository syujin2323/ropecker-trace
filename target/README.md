# 대상 프로그램: rop_vault

- `src/rop_vault.c`, `src/Makefile`은 과목 실습 저장소 [RAKKUNN/SSS-2026-CTF](https://github.com/RAKKUNN/SSS-2026-CTF)의 6주차 ROP 실습 원본입니다(수정하지 않음).
- 보호 기법: NX 켜짐, 카나리 없음, no-PIE, ASLR 켜짐. 64바이트 버퍼에 256바이트를 `read` 합니다.

## 빌드

```bash
bash target/build.sh     # Docker 필요(macOS·Windows 모두 그대로)
```

- `ubuntu:22.04`(amd64, digest 고정) 컨테이너에서 gcc 11.4.0으로 `make` 합니다(`-O0 -fno-stack-protector -no-pie -z noexecstack`).
- 같은 이미지의 `ld-linux-x86-64.so.2`와 `libc.so.6`(glibc 2.35-0ubuntu3.18)을 `sysroot/`로 꺼냅니다.
- 결과 해시와 빌드 환경 버전은 `SHA256SUMS`에 기록합니다. 다시 빌드해도 해시가 같습니다.
- 다시 빌드한 rop_vault의 주소는 과목 원본 바이너리와 같습니다(`pop rdi; ret` 0x4011de, `ret` 0x4011df, `main` 0x4012a8, `trusted_cmd` 0x404060).
- 과목이 배포한 libc는 2.35-0ubuntu3.15라 libc 내부 오프셋은 다릅니다. 이 저장소의 트레이스·gadget DB·수집은 모두 `sysroot/` 기준이므로 서로 일관됩니다.

```
target/
├── src/          과목 원본
├── build.sh
├── bin/rop_vault
├── sysroot/lib64/ld-linux-x86-64.so.2
├── sysroot/lib/x86_64-linux-gnu/libc.so.6
└── SHA256SUMS
```
