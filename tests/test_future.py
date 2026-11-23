"""future 레인 계약 예시: ret gadget의 sd로 스택의 다음 주소를 읽고 adv만큼 sp를 옮긴다.

현재 pc의 gadget은 과거 연쇄에 들어가므로 미래 연쇄에는 넣지 않는다(연쇄 길이 = past + future).
"""

from ropecker.future import future_chain
from ropecker.model import Gadget
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


def test_future_chain_stops_at_snapshot_end():
    db = FakeDB([ret_gadget(0x1000), ret_gadget(0x2000), ret_gadget(0x3000)])
    # 스냅샷이 두 칸뿐: 0x2000, 0x3000까지 읽고 그다음 슬롯은 범위 밖
    assert future_chain(0x1000, 0x7FF000, (0x2000, 0x3000), db) == [0x2000, 0x3000]


def test_future_chain_counts_jmp_gadget_then_stops():
    jmp = Gadget(addr=0x2000, n=1, end=0x2001, kind="jmp_ind", sd=None, adv=None, aligned=True, asm="jmp rax")
    db = FakeDB([ret_gadget(0x1000), jmp, ret_gadget(0x3000)])
    # jmp gadget 자체는 세지만, 그다음 목적지는 에뮬레이션 없이 알 수 없어 멈춘다
    assert future_chain(0x1000, 0x7FF000, (0x2000, 0x3000), db) == [0x2000]


def test_future_chain_stops_when_rsp_unknown():
    pivot = ret_gadget(0x2000, n=2, sd=None, adv=None, asm="pop rsp; ret")
    db = FakeDB([ret_gadget(0x1000), pivot, ret_gadget(0x3000)])
    assert future_chain(0x1000, 0x7FF000, (0x2000, 0x3000), db) == [0x2000]


def test_future_chain_respects_max_len():
    db = FakeDB([ret_gadget(0x1000)])
    stk = (0x1000,) * 100  # ret sled
    assert future_chain(0x1000, 0x7FF000, stk, db, max_len=5) == [0x1000] * 5
