"""E4: 비정렬 gadget. 코드 섹션의 모든 바이트 오프셋에서 찾는 DB는 선형 디스어셈블에 안 보이는
gadget(aligned=false)도 가져야 하고, ROPgadget(모든 오프셋 탐색)과 같은 주소 집합이어야 한다(논문 VI-A).
"""

import subprocess
import sys

from ropecker.gadgetdb import build, compare_ropgadget, scan
from ropecker.synth import ROOT, ROP_VAULT


def _compare():
    # ROPgadget의 --depth는 명령 수가 아니라 바이트 수: 6개 × 최대 15바이트 = 90
    cmd = [sys.executable, "-c", "import ropgadget; ropgadget.main()", "--binary", str(ROOT / ROP_VAULT), "--all", "--depth", "90"]
    out = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return compare_ropgadget(build(ROOT / ROP_VAULT), out)


def test_unaligned_gadget_is_in_db():
    # 'b8 5f c3 00 00' = mov eax, 0xc35f. 선형으로는 1바이트 5f c3이 보이지 않지만 +1에서 pop rdi; ret
    g = {g.addr: g for g in scan(bytes.fromhex("b85fc30000"), 0x1000)}
    assert g[0x1001].asm == "pop rdi; ret" and g[0x1001].aligned is False
    assert 0x1000 not in g  # mov 자체는 gadget이 아님


def test_rop_vault_matches_ropgadget():
    """rop_vault 전체를 ROPgadget(--all)과 대조: 서로 한쪽에만 있는 gadget이 없어야 한다(실행 전 기대)."""
    res = _compare()
    assert res["both"] > 0
    assert not res["only_rg"], f"ROPgadget만 찾은 gadget {len(res['only_rg'])}개: {[hex(a) for a in res['only_rg'][:5]]}"
    assert not res["only_ours"], f"우리만 찾은 gadget {len(res['only_ours'])}개: {[hex(a) for a in res['only_ours'][:5]]}"


def test_ropgadget_is_subset_of_ours():
    """실행 뒤 추가: ROPgadget이 찾은 것은 모두 우리 DB에 있다(우리 쪽이 더 넓을 뿐 놓친 것은 없다)."""
    res = _compare()
    assert res["both"] > 0 and not res["only_rg"]
