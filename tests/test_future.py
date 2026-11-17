"""future 레인 계약 예시: ret gadget의 sd로 스택의 다음 주소를 읽고 adv만큼 sp를 옮긴다.

현재 pc의 gadget은 과거 연쇄에 들어가므로 미래 연쇄에는 넣지 않는다(연쇄 길이 = past + future).
"""

from ropecker.future import future_chain
from tests.fakes import FakeDB, ret_gadget


def test_future_chain_follows_ret_slots_until_non_gadget():
    a = ret_gadget(0x1000, n=2, sd=8, adv=16, asm="pop rdi; ret")
    b = ret_gadget(0x2000)
    c = ret_gadget(0x3000)
    db = FakeDB([a, b, c])
    sp = 0x7FF000
    stk = (0x41, 0x2000, 0x3000, 0xDEAD)  # [pop 값][B][C][gadget 아님]
    assert future_chain(0x1000, sp, stk, db) == [0x2000, 0x3000]


def test_future_chain_empty_when_pc_is_not_a_gadget():
    db = FakeDB([ret_gadget(0x2000)])
    assert future_chain(0x9999, 0x7FF000, (0x2000,), db) == []
