"""db 레인 계약 예시: 모든 바이트 오프셋에서 '직접 분기 없이 간접 분기로 끝나는 6개 이하' 조각."""

from ropecker.gadgetdb import scan


def test_scan_pop_rdi_ret():
    gadgets = {g.addr: g for g in scan(bytes.fromhex("5fc3"), 0x1000)}  # pop rdi; ret
    g = gadgets[0x1000]
    assert (g.n, g.kind, g.sd, g.adv, g.aligned) == (2, "ret", 8, 16, True)
    r = gadgets[0x1001]
    assert (r.n, r.kind, r.sd, r.adv, r.aligned) == (1, "ret", 0, 8, True)


def test_scan_rejects_direct_branch_inside():
    addrs = {g.addr for g in scan(bytes.fromhex("eb00c3"), 0x1000)}  # jmp short +0; ret
    assert 0x1000 not in addrs  # 직접 분기를 품은 조각은 gadget이 아님
    assert 0x1002 in addrs  # ret 자체는 gadget
