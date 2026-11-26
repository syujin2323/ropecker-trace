"""E2: loop 계열(loop·loope·loopne)은 조건 분기이므로 gadget 안에 있으면 안 된다(design.md: 직접 분기 없음).

수정 전: image.classify가 loop 계열을 'other'로 분류해 `loopne X; ret` 같은 조각이 gadget DB에 들어감.
"""

import pytest

from ropecker.gadgetdb import scan

LOOPS = {"loop": "e2fe", "loope": "e1fe", "loopne": "e0fe"}  # rel8 = -2 (자기 자신으로)


@pytest.mark.parametrize("name", LOOPS)
def test_loop_family_is_not_inside_gadget(name):
    addrs = {g.addr for g in scan(bytes.fromhex(LOOPS[name] + "c3"), 0x1000)}  # <loop>; ret
    assert 0x1000 not in addrs  # 조건 분기를 품은 조각은 gadget이 아님
    assert 0x1002 in addrs  # ret 자체는 gadget


def test_jrcxz_still_excluded():  # 같은 군(jcc)의 기존 동작이 그대로인지
    assert 0x1000 not in {g.addr for g in scan(bytes.fromhex("e3fec3"), 0x1000)}


def test_shipped_db_has_no_loop_gadget():
    """저장소의 libc·rop_vault DB에 loop 계열을 품은 gadget이 없어야 한다(DB를 다시 만든 뒤 통과)."""
    import gzip
    import json
    import re

    from ropecker.synth import ROOT

    for name in ("libc.so.6", "rop_vault"):
        with gzip.open(ROOT / "data" / "gadgets" / f"{name}.gdb.jsonl.gz", "rt", encoding="utf-8") as f:
            f.readline()
            bad = [r["asm"] for r in map(json.loads, f) if re.search(r"(^|; )loop(e|ne)?\b", r["asm"])]
        assert not bad, f"{name}: loop 계열 gadget {len(bad)}개 (예: {bad[0]})"
