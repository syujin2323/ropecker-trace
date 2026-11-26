"""gadget DB (레인: db).

논문 VI-A의 IG 데이터베이스에 해당한다. 코드 섹션의 *모든 바이트 오프셋*에서 시작해
직접 분기 없이 간접 분기(ret/jmp*/call*)로 끝나는 명령 6개 이하 조각을 gadget으로 기록한다.
형식은 docs/design.md "gadget DB v1".

    uv run python -m ropecker.gadgetdb     # data/gadgets/*.gdb.jsonl.gz를 다시 만든다(항상 같은 결과)
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path

import capstone
from capstone import x86

from . import trace as trace_io
from .image import _MAX_INSN, classify, exec_segments, sha256_file
from .model import DIRECT_BRANCH_KINDS, GADGETDB_FMT, GADGETDB_V, INDIRECT_KINDS, Gadget, hx, parse_addr

ROOT = Path(__file__).resolve().parents[1]
MODULES = {  # 모듈 이름(트레이스 헤더 modules[].name) → ELF 경로
    "rop_vault": "target/bin/rop_vault",
    "libc.so.6": "target/sysroot/lib/x86_64-linux-gnu/libc.so.6",
    "ld-linux-x86-64.so.2": "target/sysroot/lib64/ld-linux-x86-64.so.2",
}
_UNKNOWN = None  # rsp 변화를 정적으로 알 수 없음(논문 Table II "need emulation")
# esp/sp/spl에 쓰면 rsp 전체가 바뀐다(esp 쓰기는 상위 32비트를 0으로) → 스택 피벗
_SP_REGS = frozenset({x86.X86_REG_RSP, x86.X86_REG_ESP, x86.X86_REG_SP, x86.X86_REG_SPL})


_PUSH = frozenset({"push", "pushf", "pushfq"})  # popcnt처럼 'pop'으로 시작하는 다른 명령과 섞이지 않게 이름 전체로 비교
_POP = frozenset({"pop", "popf", "popfq"})
_NO_STATIC_RSP = ("iret", "sysret", "sysexit")  # 스택에서 여러 값을 꺼내며 제어 흐름까지 바꾼다


def _opsize16(ins) -> bool:
    return ins.prefix[2] == 0x66  # 피연산자 크기 접두사: push/pop/ret이 2바이트를 다룬다


def _rsp_delta(ins) -> int | None:
    """명령 하나가 rsp를 얼마나 옮기는지. rsp를 안 건드리면 0, 예측할 수 없으면 None."""
    m, ops = ins.mnemonic, ins.operands
    if m in _PUSH:
        return -2 if _opsize16(ins) else -8
    if m in _POP:
        if ops and ops[0].type == x86.X86_OP_REG and ops[0].reg in _SP_REGS:
            return _UNKNOWN  # pop rsp, pop sp: 스택 피벗
        return 2 if _opsize16(ins) else 8
    if m == "enter":  # push rbp; mov rbp, rsp; sub rsp, size (중첩 수준 > 0이면 rbp 체인을 더 복사)
        if _opsize16(ins) or ops[1].imm & 0x1F:
            return _UNKNOWN
        return -(8 + (ops[0].imm & 0xFFFF))
    if m.startswith(_NO_STATIC_RSP):
        return _UNKNOWN
    rsp_dst = len(ops) == 2 and ops[0].type == x86.X86_OP_REG and ops[0].reg == x86.X86_REG_RSP
    if rsp_dst and m in ("add", "sub") and ops[1].type == x86.X86_OP_IMM:
        return ops[1].imm if m == "add" else -ops[1].imm
    if rsp_dst and m == "lea":
        mem = ops[1].mem
        if mem.base == x86.X86_REG_RSP and mem.index == 0 and mem.segment == 0:
            return mem.disp
    if _SP_REGS.intersection(ins.regs_access()[1]):
        return _UNKNOWN  # leave, mov rsp, xchg rsp, add esp 등
    return 0


def _ret_adv(ins) -> int | None:
    """ret 명령의 rsp 증가량: ret 8, ret imm16은 8+imm. retf는 cs까지 꺼내고 16비트 ret은 크기가 불확실해 모름."""
    if ins.id != x86.X86_INS_RET or _opsize16(ins):
        return _UNKNOWN
    return 8 + (ins.operands[0].imm if ins.operands else 0)


def scan(code: bytes, base: int, max_insns: int = 6) -> list[Gadget]:
    """코드 바이트(가상주소 base에서 시작)의 모든 오프셋에서 gadget을 찾는다.

    - n: gadget의 명령 개수(끝의 간접 분기 포함), end: 끝 분기 명령의 주소
    - 조각 안에 직접 분기(jmp/jcc/call)가 있거나 디코드에 실패하면 gadget이 아니다.
    - aligned: base부터 선형 디스어셈블했을 때 그 주소가 명령 경계인지
    - sd/adv: ret gadget에서 push/pop/add rsp,imm 등으로 계산 가능한 경우만, 그 밖은 None

    오프셋마다 명령 하나만 디코드하고, 끝에서 앞으로 가며 "이 명령 + 바로 다음 오프셋의 gadget"으로
    이어 붙인다(동적 계획법). 모든 오프셋에서 6개까지 디코드하는 것과 결과가 같다.
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    size = len(code)
    sizes = [0] * size  # 0 = 디코드 실패
    # chain[off] = (n, end, kind, sd, adv, asm) — off에서 시작하는 gadget, 없으면 None
    chain: list[tuple | None] = [None] * size
    for off in range(size - 1, -1, -1):
        ins = next(md.disasm(code[off : off + _MAX_INSN], base + off, 1), None)
        if ins is None:
            continue
        sizes[off] = ins.size
        kind = classify(ins)
        text = f"{ins.mnemonic} {ins.op_str}".strip()
        if kind in INDIRECT_KINDS:
            if kind == "ret":
                chain[off] = (1, base + off, kind, 0, _ret_adv(ins), text)
            else:
                chain[off] = (1, base + off, kind, None, None, text)
            continue
        if kind in DIRECT_BRANCH_KINDS:
            continue
        nxt = off + ins.size
        rest = chain[nxt] if nxt < size else None
        if rest is None or rest[0] >= max_insns:
            continue
        n, end, gkind, sd, adv, asm = rest
        delta = _rsp_delta(ins) if gkind == "ret" else None
        if delta is None or sd is None:
            sd = adv = None
        else:
            sd += delta
            adv = adv + delta if adv is not None else None
        chain[off] = (n + 1, end, gkind, sd, adv, f"{text}; {asm}")

    aligned = set()
    off = 0
    while off < size:  # 선형 스윕(objdump 방식), 디코드 실패는 1바이트 건너뜀
        aligned.add(off)
        off += sizes[off] or 1

    return [
        Gadget(base + off, c[0], c[1], c[2], c[3], c[4], off in aligned, c[5])
        for off, c in enumerate(chain)
        if c is not None
    ]


def build(elf_path: str | Path, max_insns: int = 6) -> list[Gadget]:
    """ELF 하나의 gadget 목록(주소는 ELF 가상주소 기준). 실행 세그먼트마다 scan을 부른다."""
    return [g for va, data in exec_segments(elf_path) for g in scan(data, va, max_insns)]


def _to_json(g: Gadget) -> dict:
    return {
        "off": hx(g.addr),
        "n": g.n,
        "end": hx(g.end),
        "kind": g.kind,
        "sd": g.sd,
        "adv": g.adv,
        "aligned": g.aligned,
        "asm": g.asm,
    }


def _from_json(obj: dict, base: int) -> Gadget:
    return Gadget(
        base + parse_addr(obj["off"]),
        obj["n"],
        base + parse_addr(obj["end"]),
        obj["kind"],
        obj["sd"],
        obj["adv"],
        obj["aligned"],
        obj["asm"],
    )


def save(gadgets: list[Gadget], path: str | Path, module: str, sha256: str, max_insns: int = 6) -> None:
    """gadget DB v1(jsonl.gz)로 저장. 같은 입력이면 같은 바이트(gzip mtime=0)."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    header = {
        "fmt": GADGETDB_FMT,
        "v": GADGETDB_V,
        "module": module,
        "sha256": sha256,
        "max_insns": max_insns,
    }
    with trace_io._open_text(path, "w") as f:
        f.write(json.dumps(header) + "\n")
        for g in sorted(gadgets, key=lambda g: g.addr):
            f.write(json.dumps(_to_json(g)) + "\n")


def db_path(db_dir: str | Path, module: str) -> Path:
    return Path(db_dir) / f"{module}.gdb.jsonl.gz"


class GadgetDB:
    """런타임 주소로 gadget을 찾는 조회기. 모듈별 DB를 Image의 base로 재배치해서 쓴다."""

    def __init__(self, by_addr: dict[int, Gadget]):
        self._by_addr = by_addr

    @classmethod
    def open(cls, img, db_dir: str | Path) -> "GadgetDB":
        """img.modules마다 DB를 읽는다. DB가 없거나 sha256이 다르면 ValueError."""
        by_addr: dict[int, Gadget] = {}
        for mod in img.modules:
            path = db_path(db_dir, mod.name)
            if not path.is_file():
                raise ValueError(
                    f"gadget DB가 없습니다: {path.as_posix()} (uv run python -m ropecker.gadgetdb)"
                )
            with trace_io._open_text(path, "r") as f:
                header = json.loads(f.readline())
                if header.get("fmt") != GADGETDB_FMT or header.get("v") != GADGETDB_V:
                    raise ValueError(f"{path.as_posix()}: gadget DB v1 형식이 아님")
                sha = getattr(mod, "sha256", "")
                if sha and header.get("sha256") != sha:
                    raise ValueError(
                        f"{mod.name}: gadget DB의 sha256이 모듈 파일과 다릅니다(DB를 다시 만드세요)"
                    )
                for line in f:
                    if line.strip():
                        g = _from_json(json.loads(line), mod.base)
                        by_addr[g.addr] = g
        return cls(by_addr)

    def at(self, addr: int) -> Gadget | None:
        """addr(런타임 주소)에서 시작하는 gadget, 없으면 None. 반환 Gadget.addr도 런타임 주소."""
        return self._by_addr.get(addr)

    def gadgets(self) -> list[Gadget]:
        """모든 gadget(런타임 주소 순). 합성 트레이스 도구가 조건에 맞는 gadget을 고를 때 쓴다."""
        return [self._by_addr[a] for a in sorted(self._by_addr)]

    def __len__(self) -> int:
        return len(self._by_addr)


_RG_LINE = re.compile(r"^0x([0-9a-fA-F]+) : (.+)$")
_RG_INDIRECT_END = re.compile(r"^(ret[fq]?( .*)?|jmp (?!0x).+|call (?!0x).+)$")  # ret(f), jmp·call 레지스터·메모리
_RG_DIRECT = re.compile(r"^(j\w+|call|loop\w*|xbegin) 0x[0-9a-fA-F]+$")  # 직접 분기(분기 대상이 숫자)


def compare_ropgadget(gadgets: list[Gadget], rg_output: str, max_insns: int = 6) -> dict:
    """ROPgadget 출력과 교차검증: {'only_ours': [...], 'only_rg': [...], 'both': n}.

    주소(가상주소)만 비교한다. rg_output은 `ROPgadget --binary <ELF> --all --depth <n>`의 표준 출력이다.
    ROPgadget은 syscall·int 0x80으로 끝나는 조각과 직접 분기를 품은 조각도 내므로, 우리 정의(직접 분기 없이
    간접 분기 ret·jmp*·call*로 끝나는 max_insns개 이하)에 해당하는 줄만 남긴다. 주소 목록은 오름차순이다.
    """
    theirs = set()
    for line in rg_output.splitlines():
        m = _RG_LINE.match(line.strip())
        if not m:
            continue
        insns = [i.strip() for i in m.group(2).split(" ; ")]
        if len(insns) <= max_insns and _RG_INDIRECT_END.match(insns[-1]) and not any(map(_RG_DIRECT.match, insns)):
            theirs.add(int(m.group(1), 16))
    ours = {g.addr for g in gadgets}
    return {"only_ours": sorted(ours - theirs), "only_rg": sorted(theirs - ours), "both": len(ours & theirs)}


def main() -> int:
    out = ROOT / "data" / "gadgets"
    for name, rel in MODULES.items():
        t0 = time.perf_counter()
        elf = ROOT / rel
        gadgets = build(elf)
        save(gadgets, db_path(out, name), name, sha256_file(elf))
        n_ret = sum(g.kind == "ret" for g in gadgets)
        n_sd = sum(g.sd is not None for g in gadgets)
        n_al = sum(g.aligned for g in gadgets)
        print(
            f"{name}: gadget {len(gadgets):,}개 (ret {n_ret:,}, sd 계산 {n_sd:,}, 정렬 {n_al:,}) "
            f"→ {db_path(out, name).relative_to(ROOT).as_posix()} ({time.perf_counter() - t0:.1f}s)"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
