"""past 레인 계약 예시: 최신 LBR 항목부터 거꾸로, 목적지가 gadget인 동안 센다."""

from ropecker.model import Branch
from ropecker.past import past_chain
from tests.fakes import FakeDB, ret_gadget


def test_past_chain_counts_consecutive_gadget_destinations():
    db = FakeDB([ret_gadget(0x1000), ret_gadget(0x2000), ret_gadget(0x3000)])
    lbr = [
        Branch(1, 0x500, 0x9999, "ret"),  # 목적지가 gadget이 아님 → 여기서 끊김
        Branch(5, 0x600, 0x1000, "ret"),
        Branch(6, 0x1000, 0x2000, "ret"),
        Branch(7, 0x2000, 0x3000, "ret"),
    ]
    addrs, unaligned = past_chain(lbr, db)
    assert addrs == [0x1000, 0x2000, 0x3000]
    assert unaligned is False
