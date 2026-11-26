"""db 레인 계약 예시: 모든 바이트 오프셋에서 '직접 분기 없이 간접 분기로 끝나는 6개 이하' 조각."""

import pytest

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


def test_scan_stack_offsets_and_kinds():
    def first(hexcode):
        return scan(bytes.fromhex(hexcode), 0x1000)[0]

    assert (first("4883c408c3").sd, first("4883c408c3").adv) == (8, 16)  # add rsp, 8; ret
    assert (first("5f5ec3").sd, first("5f5ec3").adv) == (16, 24)  # pop rdi; pop rsi; ret (x86-64: +24)
    assert first("c21000").adv == 24  # ret 0x10
    for pivot in ("c9c3", "5cc3", "4889c4c3"):  # leave / pop rsp / mov rsp, rax; ret → 정적으로 모름
        assert first(pivot).sd is None and first(pivot).adv is None
    jmp = first("ffe0")  # jmp rax
    assert (jmp.kind, jmp.sd, jmp.adv) == ("jmp_ind", None, None)
    assert not any(
        g.addr == 0x1000 for g in scan(bytes.fromhex("5f5e5a5958415841595f5ec3"), 0x1000)
    )  # 7개 이상


def test_save_open_relocates(tmp_path):
    from types import SimpleNamespace

    from ropecker.gadgetdb import GadgetDB, save

    save(scan(bytes.fromhex("5fc3"), 0x1000), tmp_path / "m.gdb.jsonl.gz", "m", "ab" * 32)
    img = SimpleNamespace(modules=[SimpleNamespace(name="m", base=0x7F0000000000, sha256="ab" * 32)])
    db = GadgetDB.open(img, tmp_path)
    g = db.at(0x7F0000001000)
    assert (g.addr, g.end, g.asm, g.sd) == (0x7F0000001000, 0x7F0000001001, "pop rdi; ret", 8)
    assert db.at(0x1000) is None

    img.modules[0].sha256 = "cd" * 32  # 다른 파일로 만든 DB는 거부
    with pytest.raises(ValueError):
        GadgetDB.open(img, tmp_path)


def test_loop_family_is_conditional_branch():
    """E2 회귀: loop·loope·loopne을 품은 조각은 gadget이 아니다(jrcxz와 같음)."""
    for op in ("e2", "e1", "e0", "e3"):
        assert 0x1000 not in {g.addr for g in scan(bytes.fromhex(op + "fec3"), 0x1000)}


def test_rsp_delta_edge_instructions():
    """E3 회귀: popcnt는 pop이 아니고, 16비트 push는 2바이트, enter n,0은 8+n, iretq는 모름."""
    def first(h):
        g = {g.addr: g for g in scan(bytes.fromhex(h), 0x1000)}[0x1000]
        return g.sd, g.adv

    assert first("f3480fb8c3c3") == (0, 8)
    assert first("6650c3") == (-2, 6)
    assert first("c8080000c3") == (-16, -8)
    assert first("48cfc3") == (None, None)


def test_compare_ropgadget_filters_to_our_definition():
    """E4: ROPgadget 줄 중 직접 분기를 품었거나 6개 초과, syscall로 끝나는 것은 대조에서 뺀다."""
    from ropecker.gadgetdb import compare_ropgadget
    from ropecker.model import Gadget

    rg = "\n".join([
        "Gadgets information", "=" * 60,
        "0x0000000000001000 : pop rdi ; ret",
        "0x0000000000001001 : ret",
        "0x0000000000001002 : jmp 0x1100",  # 직접 분기: 제외
        "0x0000000000001003 : add eax, 1 ; jne 0x1000 ; ret",  # 직접 분기를 품음: 제외
        "0x0000000000001004 : syscall",  # 끝이 syscall: 제외
        "0x0000000000001005 : pop rax ; pop rbx ; pop rcx ; pop rdx ; pop rsi ; pop rdi ; ret",  # 7개: 제외
        "0x0000000000001010 : jmp rax",
        "Unique gadgets found: 7",
    ])
    mk = lambda a, kind: Gadget(a, 1, a, kind, None, None, True, "x")  # noqa: E731
    res = compare_ropgadget([mk(0x1000, "ret"), mk(0x1001, "ret"), mk(0x1020, "ret")], rg)
    assert res == {"only_ours": [0x1020], "only_rg": [0x1010], "both": 2}
