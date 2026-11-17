"""scripts/run_cases.py(보호 적용 전·후 비교표) 검사. 실제로 CLI를 별도 프로세스로 돌린다."""

import json
from pathlib import Path

from ropecker.cases import TRACE_KINDS, iter_checks, load_frozen, trace_path
from scripts import run_cases

ROOT = Path(__file__).resolve().parents[1]


def test_run_cases_writes_table_and_logs(tmp_path):
    code = run_cases.main(["--out", str(tmp_path)])

    data = load_frozen(ROOT)
    traces = [(chk["id"], kind) for _, chk in iter_checks(data) for kind in TRACE_KINDS]
    present = [(cid, kind) for cid, kind in traces if (ROOT / trace_path(cid, kind)).exists()]
    md = (tmp_path / "compare.md").read_text(encoding="utf-8")
    rows = [line for line in md.splitlines() if line.startswith("| ") and not line.startswith("| 사례")]
    assert len(rows) == len(present)

    for cid, kind in present:
        for mode in ("before", "after"):
            assert (tmp_path / "runs" / f"{cid}-{kind}.{mode}.log").exists()
    with open(tmp_path / "runs" / "f2-violation-synth.before.json", encoding="utf-8") as f:
        before = json.load(f)
    assert before["trace_end"] == "syscall:59"
    assert "execve 도달 = 셸 실행" in md

    # 로그의 명령은 저장소 기준 상대 경로('/' 구분)라 어느 OS에서든 그대로 다시 실행할 수 있다
    log = (tmp_path / "runs" / "f2-violation-synth.before.log").read_text(encoding="utf-8")
    assert log.startswith("$ python -m ropecker --trace traces/synth/f2-violation.jsonl.gz --window 8192 ")
    assert log.rstrip().endswith("[종료 코드 0]")
    assert code == 0  # 미구현은 실패가 아니고, 구현된 뒤에는 기대와 다르면 1


BEFORE_EXECVE = {"code": 0, "stderr": "", "result": {"steps": 24, "trace_end": "syscall:59"}}


def _after(step: int) -> dict:
    return {
        "code": 1,
        "stderr": "",
        "result": {"verdict": "ROP", "chain_len": 17, "checkpoint": {"step": step}},
    }


def test_describe_after_marks_whether_damage_was_prevented():
    assert (
        run_cases.describe_after(_after(3), BEFORE_EXECVE)
        == "ROP, 연쇄 17, 스텝 3에서 중단 (execve 전, 피해 제거)"
    )
    assert (
        run_cases.describe_after(_after(23), BEFORE_EXECVE)
        == "ROP, 연쇄 17, 스텝 23에서 중단 (execve 뒤, 피해 발생)"
    )


def test_stub_is_pending_but_error_fails():
    stub = {
        "code": 2,
        "stderr": "미구현: past.past_chain: past 레인(W12) (README의 '진행 현황' 참고)\n",
        "result": None,
    }
    assert run_cases.describe_after(stub, BEFORE_EXECVE) == "미구현 (past.past_chain)"
    assert run_cases.status({"verdict": "ROP"}, stub) == ("⏳ 미구현", False)
    error = {"code": 2, "stderr": "오류: sha256 불일치\n", "result": None}
    assert run_cases.status({"verdict": "ROP"}, error) == ("⚠️ 오류", True)
    wrong = {"code": 0, "stderr": "", "result": {"verdict": "정상", "chain_len": 3, "gadgets": []}}
    assert run_cases.status({"verdict": "ROP", "chain_len_min": 11}, wrong) == (
        "❌ 불일치: 판정 정상 (기대 ROP); 연쇄 3 (기대 ≥ 11)",
        True,
    )
