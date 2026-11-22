"""통합 판정 계약 예시: 체크포인트마다 과거 + 미래 연쇄를 더해 ≥ T에서 멈춘다(가짜 이미지·DB)."""

from ropecker.detector import _tmp_checkpoints, detect
from ropecker.model import Insn, Params, Step, Trace
from tests.fakes import FakeDB, FakeImage, ret_gadget

PAGE = 4096


def _chain_trace(n: int) -> tuple[Trace, FakeImage, FakeDB]:
    """ret gadget n개가 각각 다른 페이지에서 ret으로 이어지는 트레이스(앞에 정상 코드 한 스텝)."""
    addrs = [0x100000 + i * PAGE for i in range(n)]
    insns = {0x1000: Insn(1, "ret", "ret"), **{a: Insn(1, "ret", "ret") for a in addrs}}
    steps = [Step(0x1000, sp=0x7000, stk=(addrs[0],))]
    steps += [Step(a, sp=0x7008 + 8 * i, stk=()) for i, a in enumerate(addrs)]
    steps.append(Step(0x9999000, sp=0, stk=()))  # gadget이 아닌 곳에 착지
    tr = Trace(header={}, steps=steps, end={"end": "exit", "code": 0})
    return tr, FakeImage(insns), FakeDB([ret_gadget(a) for a in addrs])


def test_detect_stops_at_first_rop_checkpoint():
    tr, img, db = _chain_trace(12)
    res = detect(tr, img, db, Params(window=4096, threshold=11))
    assert res["verdict"] == "ROP"
    assert res["chain_len"] == 11 and res["checks"][-1]["total"] == 11
    assert res["checkpoint"]["step"] == 11  # 11번째 gadget 진입(스텝 11)에서 멈춤
    assert [g["from"] for g in res["gadgets"]] == ["past"] * res["past_len"] + ["future"] * res["future_len"]
    assert res["n_checkpoints"] == len(res["checks"])


def test_detect_normal_reports_max_chain():
    tr, img, db = _chain_trace(10)
    res = detect(tr, img, db, Params(window=4096, threshold=11))
    assert res["verdict"] == "정상"
    assert res["chain_len"] == 10 == max(c["total"] for c in res["checks"])
    assert res["trace_end"] == "exit:0"


def test_tmp_checkpoints_window_and_risky_syscall():
    steps = [Step(0x1000), Step(0x1001), Step(0x2000), Step(0x1002), Step(0x3000), Step(0x1003, sys=59)]
    tr = Trace(header={}, steps=steps)
    # 페이지 2개 LRU: 0x3000 진입 때 가장 오래된 0x2 페이지가 빠지고, 0x1 페이지는 남는다
    assert list(_tmp_checkpoints(tr, 8192, frozenset({59}))) == [
        (0, "window"),
        (2, "window"),
        (4, "window"),
        (5, "syscall:59"),
    ]
