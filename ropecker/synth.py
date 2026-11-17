"""합성 트레이스 생성 — 동결 사례(정상·위반 17·경계 11/10)의 기준 트레이스.

    uv run python -m ropecker.synth        # traces/synth/*.jsonl.gz 4개를 다시 만든다(항상 같은 결과)

rop_vault(6주차 실습 바이너리)와 sysroot libc의 *실제* 명령 주소만 쓴다. 체인은 libc의 단순 gadget
(ret, pop r; ret)을 서로 다른 코드 페이지에서 골라 이어 붙여, 체인 안에서 윈도 밖 실행(체크포인트)이
생기게 한다. 정답(연쇄를 이룬 gadget 주소)은 헤더 'truth'에 넣는다.
보고서에는 "같은 바이너리 주소로 구성한 합성 트레이스"라고 밝힌다.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from elftools.elf.elffile import ELFFile

from . import trace as trace_io
from .image import Image, exec_segments, module_entry
from .model import TRACE_FMT, TRACE_V, Step, Trace, hx

ROOT = Path(__file__).resolve().parents[1]
ROP_VAULT = "target/bin/rop_vault"
LIBC = "target/sysroot/lib/x86_64-linux-gnu/libc.so.6"
LIBC_BASE = 0x7FFFF7D80000  # 합성용 libc 로드 주소(페이지 정렬)
FRAME = 0x7FFFFFFDE000  # 합성용 스택: vuln 복귀 주소 슬롯의 주소
PAGE = 4096
QWORD = 8
STACK_QWORDS = 32
FILL = 0x4141414141414141  # 버퍼를 넘친 'A'

GADGET_BYTES = {"ret": b"\xc3", "rdi": b"\x5f\xc3", "rsi": b"\x5e\xc3", "rax": b"\x58\xc3"}
POP_VALUE = {"rdi": 0x404060, "rsi": 0, "rax": 59}  # rdi = trusted_cmd("/bin/sh"), rax = execve
# glibc syscall 래퍼: syscall; cmp rax, -4096; ja … → 직접 분기가 있어 gadget이 아니다
SYSCALL_SITE = b"\x0f\x05\x48\x3d\x00\xf0\xff\xff\x77"
LIBC_MAIN_RET = b"\xff\xd0\x89\xc7\xe8"  # call rax(main); mov edi, eax; call exit

CASES = {
    # check id: (gadget 종류 목록, 끝 처리)
    "f2-violation": (["ret"] * 14 + ["rdi", "rsi", "rax"], "execve"),
    "f3-boundary-11": (["ret"] * 8 + ["rdi", "rsi", "rax"], "stop"),
    "f3-boundary-10": (["ret"] * 7 + ["rdi", "rsi", "rax"], "stop"),
}


@dataclass(frozen=True)
class Gad:
    addr: int
    reg: str | None  # None = 'ret', 아니면 'pop <reg>; ret'

    @property
    def slots(self) -> int:
        return 1 + (1 if self.reg else 0)


class _Machine:
    """rsp와 스택 메모리를 추적하며 스텝을 기록한다(페이지가 바뀐 스텝·syscall 스텝에 스냅샷)."""

    def __init__(self, mem: dict[int, int], rsp: int):
        self.mem, self.rsp = mem, rsp
        self.steps: list[Step] = []
        self._page: int | None = None

    def emit(self, pc: int, sys: int | None = None) -> None:
        page = pc // PAGE
        if page != self._page or sys is not None:
            stk = tuple(self.mem.get(self.rsp + QWORD * i, 0) for i in range(STACK_QWORDS))
            self.steps.append(Step(pc=pc, sp=self.rsp, stk=stk, sys=sys))
        else:
            self.steps.append(Step(pc=pc))
        self._page = page

    def pop(self) -> int:
        value = self.mem.get(self.rsp, 0)
        self.rsp += QWORD
        return value


def _symbols(path: Path) -> dict[str, int]:
    with open(path, "rb") as f:
        tab = ELFFile(f).get_section_by_name(".symtab")
        return {s.name: s["st_value"] for s in tab.iter_symbols() if s.name}


def _find_all(path: Path, pattern: bytes, base: int) -> list[int]:
    out = []
    for va, data in exec_segments(path):
        i = data.find(pattern)
        while i >= 0:
            out.append(base + va + i)
            i = data.find(pattern, i + 1)
    return out


def _walk(img: Image, start: int, until_text: str, limit: int = 64) -> list[int]:
    """start부터 선형으로 명령 주소를 모은다(until_text로 시작하는 명령까지 포함)."""
    out, pc = [], start
    for _ in range(limit):
        out.append(pc)
        ins = img.insn(pc)
        if ins.text.startswith(until_text):
            return out
        pc += ins.size
    raise ValueError(f"{hex(start)}부터 '{until_text}'를 찾지 못함")


class Builder:
    def __init__(self, root: Path = ROOT):
        self.root = root
        self.modules = [module_entry("rop_vault", ROP_VAULT, 0, root), module_entry("libc.so.6", LIBC, LIBC_BASE, root)]
        self.img = Image.from_header({"modules": self.modules}, root=root)
        sym = _symbols(root / ROP_VAULT)
        self.vuln_tail = [sym["main"] - 3, sym["main"] - 2, sym["main"] - 1]  # nop; leave; ret
        assert [self.img.insn(a).text for a in self.vuln_tail] == ["nop", "leave", "ret"], "vuln 끝이 예상과 다름"
        self.main_after_vuln = self._main_return_site(sym)
        sites = _find_all(root / LIBC, SYSCALL_SITE, LIBC_BASE)
        self.syscall_site = sites[0]
        self.libc_main_ret = next(iter(_find_all(root / LIBC, LIBC_MAIN_RET, LIBC_BASE)), None)

    def _main_return_site(self, sym: dict[str, int]) -> int:
        pc, vuln = sym["main"], sym["vuln"]
        for _ in range(128):
            ins = self.img.insn(pc)
            if ins.kind == "call" and ins.text.endswith(hex(vuln)):
                return pc + ins.size
            pc += ins.size
        raise ValueError("main에서 vuln 호출을 찾지 못함")

    def pick_chain(self, kinds: list[str]) -> list[Gad]:
        """종류별로 libc gadget을 고르되, 모든 gadget이 서로 다른 코드 페이지에 있게 한다."""
        used = {self.syscall_site // PAGE}
        chain = []
        for kind in kinds:
            for addr in _find_all(self.root / LIBC, GADGET_BYTES[kind], LIBC_BASE):
                last = addr + len(GADGET_BYTES[kind]) - 1
                if addr // PAGE in used or last // PAGE != addr // PAGE:
                    continue
                if kind == "ret":
                    ok = self.img.insn(addr).text == "ret"
                else:
                    ok = self.img.insn(addr).text == f"pop {kind}" and self.img.insn(addr + 1).text == "ret"
                if ok:
                    used.add(addr // PAGE)
                    chain.append(Gad(addr, None if kind == "ret" else kind))
                    break
            else:
                raise ValueError(f"서로 다른 페이지의 '{kind}' gadget이 부족함")
        return chain

    def header(self, check_id: str, truth: dict) -> dict:
        return {
            "fmt": TRACE_FMT,
            "v": TRACE_V,
            "collector": "synth",
            "case": check_id,
            "argv": ["rop_vault"],
            "stack_qwords": STACK_QWORDS,
            "modules": self.modules,
            "truth": truth,
            "note": "rop_vault(6주차 실습 바이너리)·sysroot libc의 실제 주소로 구성한 합성 트레이스",
        }

    def chain_trace(self, check_id: str, kinds: list[str], ending: str) -> Trace:
        chain = self.pick_chain(kinds)
        landing = self.syscall_site if ending == "execve" else self.syscall_site + 2  # cmp; ja … (gadget 아님)
        mem: dict[int, int] = {a: FILL for a in range(FRAME - 0x48, FRAME, QWORD)}  # buf 64 + saved rbp
        slot = FRAME
        for g in chain:
            mem[slot] = g.addr
            slot += QWORD
            if g.reg:
                mem[slot] = POP_VALUE[g.reg]
                slot += QWORD
        mem[slot] = landing
        if (slot - FRAME) // QWORD > STACK_QWORDS:
            raise ValueError("체인이 스냅샷(32 qword)보다 김")

        m = _Machine(mem, rsp=FRAME - 0x58)
        nop, leave, ret = self.vuln_tail
        m.emit(nop)
        m.emit(leave)
        m.rsp = FRAME  # leave: rsp = rbp(FRAME-8), pop rbp
        m.emit(ret)
        first_check = len(m.steps)
        expected = [g.addr for g in chain] + [landing]
        for i, g in enumerate(chain):
            assert m.pop() == expected[i]
            if g.reg:
                m.emit(g.addr)  # pop reg
                m.pop()
                m.emit(g.addr + 1)  # ret
            else:
                m.emit(g.addr)  # ret
        assert m.pop() == landing
        if ending == "execve":
            m.emit(landing, sys=59)
            end = {"end": "syscall", "sys": 59}
        else:
            m.emit(landing)
            end = {"end": "max_steps"}
        truth = {"chain": [hx(g.addr) for g in chain], "chain_len": len(chain), "first_checkpoint_step": first_check}
        return Trace(header=self.header(check_id, truth), steps=m.steps, end=end)

    def normal_trace(self) -> Trace:
        """정상 입력: vuln이 main으로 정상 복귀 → main이 libc로 복귀 → exit 호출."""
        r1 = self.main_after_vuln
        main_tail = _walk(self.img, r1, "ret")  # mov eax, 0; leave; ret
        mem = {FRAME - 0x48: int.from_bytes(b"hello\n\0\0", "little"), FRAME - QWORD: FRAME + 0x20, FRAME: r1}
        if self.libc_main_ret is not None:
            libc_site = self.libc_main_ret + 2  # mov edi, eax; call exit
            mem[FRAME + 0x28] = libc_site
        m = _Machine(mem, rsp=FRAME - 0x58)
        nop, leave, ret = self.vuln_tail
        m.emit(nop)
        m.emit(leave)
        m.rsp = FRAME
        m.emit(ret)
        assert m.pop() == r1
        for pc in main_tail:
            m.emit(pc)
            if self.img.insn(pc).text == "leave":
                m.rsp = FRAME + 0x28  # rsp = rbp(FRAME+0x20), pop rbp
        if self.libc_main_ret is not None:
            assert m.pop() == libc_site
            for pc in _walk(self.img, libc_site, "call"):
                m.emit(pc)
        truth = {"chain": [], "chain_len_max": 0, "first_checkpoint_step": 0}
        return Trace(header=self.header("f1-normal", truth), steps=m.steps, end={"end": "exit", "code": 0})

    def build_all(self) -> dict[str, Trace]:
        out = {"f1-normal": self.normal_trace()}
        for check_id, (kinds, ending) in CASES.items():
            out[check_id] = self.chain_trace(check_id, kinds, ending)
        return out


def main() -> int:
    out_dir = ROOT / "traces" / "synth"
    for check_id, tr in Builder().build_all().items():
        problems = trace_io.validate(tr)
        if problems:
            raise SystemExit(f"{check_id}: {problems}")
        path = out_dir / f"{check_id}.jsonl.gz"
        trace_io.dump(tr, path)
        print(f"{path.relative_to(ROOT).as_posix()}: 스텝 {len(tr.steps)}, 정답 {tr.header['truth']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
