"""형식 예시(단위 check): gadget DB가 6주차 풀이 주소(0x4011de)를 'pop rdi; ret' gadget으로 아는지.

추가 사례의 단위 check는 이렇게 cases/extra/ 아래에 pytest 테스트를 두고, 사례 파일의 check에
"pytest": "<파일>::<테스트 이름>", "expect": {"pass": true}로 적는다.
기본 `uv run pytest`(tests/만 수집)에는 들어가지 않고 `scripts/run_cases.py --cases`가 실행한다.
"""

from ropecker.gadgetdb import GadgetDB
from ropecker.image import Image, module_entry
from ropecker.synth import LIBC, LIBC_BASE, ROOT, ROP_VAULT  # ROOT = 저장소 루트(파일을 어디로 옮겨도 같음)


def test_pop_rdi_ret_is_gadget():
    modules = [module_entry("rop_vault", ROP_VAULT, 0, ROOT), module_entry("libc.so.6", LIBC, LIBC_BASE, ROOT)]
    img = Image.from_header({"modules": modules}, root=ROOT)
    g = GadgetDB.open(img, ROOT / "data" / "gadgets").at(0x4011DE)
    assert g is not None
    assert (g.asm, g.kind, g.sd, g.adv, g.aligned) == ("pop rdi; ret", "ret", 8, 16, True)
