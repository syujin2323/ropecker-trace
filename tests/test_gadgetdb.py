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
