"""past 레인 계약 예시: LBR 흉내(간접 분기만 기록)."""

from ropecker.lbr import branches, lbr_at
from ropecker.model import Branch, Insn, Step, Trace
from tests.fakes import FakeImage


def test_branches_records_only_taken_indirect():
    insns = {
        0x10: Insn(1, "other", "nop"),
        0x11: Insn(1, "ret", "ret"),
        0x50: Insn(1, "other", "nop"),
        0x51: Insn(2, "jmp", "jmp 0x60"),  # 직접 분기는 LBR 필터에서 뺀다
        0x60: Insn(1, "other", "nop"),
    }
    tr = Trace(header={}, steps=[Step(a) for a in (0x10, 0x11, 0x50, 0x51, 0x60)], end={"end": "exit", "code": 0})
    assert branches(tr, FakeImage(insns)) == [Branch(step=1, src=0x11, dst=0x50, kind="ret")]


def test_lbr_at_keeps_most_recent_depth_before_step():
    brs = [Branch(i, i, i + 100, "ret") for i in range(20)]
    assert [b.step for b in lbr_at(brs, step=18, depth=16)] == list(range(2, 18))
