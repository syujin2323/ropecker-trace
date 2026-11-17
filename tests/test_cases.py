from pathlib import Path

import pytest

from ropecker.cases import TRACE_KINDS, describe_expect, iter_checks, judge, load_frozen, trace_path

ROOT = Path(__file__).resolve().parents[1]


def test_every_frozen_check_has_a_synth_trace():
    data = load_frozen(ROOT)
    ids = [chk["id"] for _, chk in iter_checks(data)]
    assert ids == ["f1-normal", "f2-violation", "f3-boundary-11", "f3-boundary-10"]
    for check_id in ids:
        assert (ROOT / trace_path(check_id, "synth")).exists()
    assert TRACE_KINDS == ("synth", "real")


def test_describe_expect():
    assert (
        describe_expect({"verdict": "정상", "chain_len_max": 10, "trace_end": "exit:0"})
        == "정상, 연쇄 ≤ 10, 끝 exit:0"
    )
    assert describe_expect({"verdict": "ROP", "chain_len_min": 11, "gadgets_nonempty": True}) == (
        "ROP, 연쇄 ≥ 11, gadget 주소 출력"
    )
    assert describe_expect({"verdict": "ROP", "chain_len": 11}) == "ROP, 연쇄 = 11"


def test_judge_match_and_each_mismatch():
    rop = {"verdict": "ROP", "chain_len": 17, "gadgets": [{"addr": "0x1"}], "trace_end": "syscall:59"}
    assert judge({"verdict": "ROP", "chain_len_min": 11, "gadgets_nonempty": True}, rop) == []
    assert judge({"verdict": "정상", "chain_len_max": 10}, rop) == [
        "판정 ROP (기대 정상)",
        "연쇄 17 (기대 ≤ 10)",
    ]
    assert judge({"verdict": "ROP", "chain_len": 11}, rop) == ["연쇄 17 (기대 = 11)"]
    assert judge({"verdict": "ROP", "gadgets_nonempty": True}, {**rop, "gadgets": []}) == [
        "연쇄를 이룬 gadget 주소가 출력되지 않음"
    ]
    normal = {"verdict": "정상", "chain_len": 3, "gadgets": [], "trace_end": "signal:11"}
    assert judge({"verdict": "정상", "chain_len_max": 10, "trace_end": "exit:0"}, normal) == [
        "끝 signal:11 (기대 exit:0)"
    ]
    assert judge({"verdict": "ROP", "chain_len_min": 11}, {"verdict": "ROP", "chain_len": None}) == [
        "연쇄 None (기대 ≥ 11)"
    ]


def test_unknown_expect_key_is_rejected():
    with pytest.raises(ValueError):
        judge({"verdict": "ROP", "chain_len_atleast": 11}, {"verdict": "ROP"})
