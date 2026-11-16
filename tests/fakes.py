"""레인별 단위 테스트용 가짜 객체. 실제 ELF·DB 없이 계약(model.py)만으로 테스트한다."""

from __future__ import annotations

from ropecker.model import TRACE_FMT, TRACE_V, Gadget, Insn, Step, Trace


class FakeImage:
    """주소 → Insn 사전. 없는 주소는 1바이트 'other' 명령으로 본다."""

    def __init__(self, insns: dict[int, Insn]):
        self._insns = insns

    def insn(self, addr: int) -> Insn:
        return self._insns.get(addr, Insn(1, "other", "nop"))

    def locate(self, addr: int) -> tuple[str, int] | None:
        return ("fake", addr)


class FakeDB:
    """주소 → Gadget 사전."""

    def __init__(self, gadgets: list[Gadget]):
        self._by_addr = {g.addr: g for g in gadgets}

    def at(self, addr: int) -> Gadget | None:
        return self._by_addr.get(addr)


def ret_gadget(addr: int, n: int = 1, sd: int = 0, adv: int | None = 8, asm: str = "ret") -> Gadget:
    """ret으로 끝나는 gadget. 'ret'은 sd=0·adv=8, 'pop rdi; ret'은 n=2·sd=8·adv=16."""
    return Gadget(addr=addr, n=n, end=addr + n - 1, kind="ret", sd=sd, adv=adv, aligned=True, asm=asm)


def tiny_trace() -> Trace:
    """형식 검사용 작은 트레이스(모듈 sha256은 가짜라 실제 분석에는 쓸 수 없음)."""
    header = {
        "fmt": TRACE_FMT,
        "v": TRACE_V,
        "collector": "synth",
        "modules": [{"name": "rop_vault", "path": "target/bin/rop_vault", "sha256": "0" * 64, "base": "0x0"}],
    }
    steps = [
        Step(0x401136),
        Step(0x40113A, sp=0x7FFD0000, stk=(0x401200, 0x0)),
        Step(0x401140),
    ]
    return Trace(header=header, steps=steps, end={"end": "exit", "code": 0})
