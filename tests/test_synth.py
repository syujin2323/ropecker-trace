"""합성 트레이스(동결 사례 기준)가 생성기와 일치하고, 정답·형식이 맞는지 확인한다."""

from pathlib import Path

import pytest

from ropecker import trace as trace_io
from ropecker.image import Image
from ropecker.synth import Builder

ROOT = Path(__file__).resolve().parents[1]
EXPECTED_LEN = {"f1-normal": 0, "f2-violation": 17, "f3-boundary-11": 11, "f3-boundary-10": 10}


@pytest.fixture(scope="module")
def built():
    return Builder(ROOT).build_all()


@pytest.mark.parametrize("check_id", sorted(EXPECTED_LEN))
def test_committed_trace_matches_generator(built, check_id):
    """커밋된 traces/synth 파일이 `python -m ropecker.synth` 결과와 같아야 한다(재생성 누락 방지)."""
    on_disk = trace_io.load(ROOT / "traces" / "synth" / f"{check_id}.jsonl.gz")
    fresh = built[check_id]
    assert on_disk.header == fresh.header
    assert on_disk.steps == fresh.steps
    assert on_disk.end == fresh.end


@pytest.mark.parametrize("check_id", sorted(EXPECTED_LEN))
def test_truth_and_format(built, check_id):
    tr = built[check_id]
    assert trace_io.validate(tr) == []
    assert len(tr.header["truth"]["chain"]) == EXPECTED_LEN[check_id]
    img = Image.from_header(tr.header, root=ROOT)
    for a in tr.header["truth"]["chain"]:
        assert img.insn(int(a, 16)).text in ("ret", "pop rdi", "pop rsi", "pop rax")
    # 실행 페이지가 바뀐 스텝에는 스냅샷(sp·stk)이 있어야 한다
    prev = None
    for s in tr.steps:
        if prev is None or s.pc // 4096 != prev:
            assert s.sp is not None and s.stk is not None
        prev = s.pc // 4096


def test_violation_reaches_execve_before_protection(built):
    """보호 적용 전 피해: 위반 트레이스는 execve(59)에 도달한다(보호 적용 후에는 그 전에 멈춰야 함)."""
    tr = built["f2-violation"]
    assert tr.end == {"end": "syscall", "sys": 59}
    assert tr.steps[-1].sys == 59
