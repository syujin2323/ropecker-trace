# W12 재현 확인 (collect 레인 · 안세진)

## 위반 입력(f2-violation) 결정적 수집

- 환경: Windows 11 + Docker Desktop (rc-collect 이미지, qemu-user + gdb-multiarch)
- 수집 명령: docker run --rm -v "${PWD}:/w" -w /w rc-collect bash collect/run.sh f2-violation
- 1차 수집 후 SHA256: A88566C39EA43B51FAEF95B99011E57E8F89EE404495164CAA2488B249CB3422
- 동일 입력 2차 수집 후 git status: nothing to commit, working tree clean
  → 두 번의 수집 결과가 바이트 단위로 동일(결정적 수집 확인)
- 트레이스: 8,445 스텝, 끝 행 {"end":"syscall","sys":59} (execve 도달)

## 결정적 수집의 근거
- env -i로 환경변수 제거, qemu -seed 1로 ASLR 고정
- 트레이스는 mtime=0으로 gzip 저장 → 압축 결과까지 재현
