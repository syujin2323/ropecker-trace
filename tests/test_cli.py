import json
from pathlib import Path

import pytest

from ropecker import cli
from ropecker import trace as trace_io
from tests.fakes import tiny_trace

ROOT = Path(__file__).resolve().parents[1]


def test_help_exits_zero():
    with pytest.raises(SystemExit) as e:
        cli.main(["--help"])
    assert e.value.code == 0


def test_no_check_is_before_protection_summary(tmp_path, capsys):
    path = tmp_path / "t.log"
    trace_io.dump(tiny_trace(), path)
    out_json = tmp_path / "result.json"
    code = cli.main(
        ["--trace", str(path), "--window", "8192", "--threshold", "11", "--no-check", "--json", str(out_json)]
    )
    assert code == 0
    assert "미검사" in capsys.readouterr().out
    with open(out_json, encoding="utf-8") as f:
        result = json.load(f)
    assert result["verdict"] == "미검사"
    assert result["steps"] == 3
    assert result["trace_end"] == "exit:0"
    assert result["params"]["threshold"] == 11
    assert result["checks"] == []  # 보호 적용 전에는 방어자 판정 로그가 없다


def test_verbose_prints_defender_log(monkeypatch, capsys):
    """--verbose는 체크포인트별 판정 로그(checks)를 출력한다. detect는 가짜 결과로 바꿔 CLI 출력만 본다."""
    from ropecker import detector, gadgetdb

    fake = {
        "verdict": "ROP",
        "chain_len": 17,
        "past_len": 1,
        "future_len": 16,
        "gadgets": [],
        "checkpoint": {"step": 3, "pc": "0x7ffff7d9c000", "reason": "window"},
        "checks": [
            {"step": 0, "pc": "0x4011f5", "reason": "window", "past": 0, "future": 0, "total": 0},
            {"step": 3, "pc": "0x7ffff7d9c000", "reason": "window", "past": 1, "future": 16, "total": 17},
        ],
        "n_checkpoints": 2,
        "steps": 24,
        "trace_end": "syscall:59",
        "params": {"threshold": 11, "cmp": "ge"},
    }
    monkeypatch.setattr(gadgetdb.GadgetDB, "open", classmethod(lambda cls, img, db_dir: None))
    monkeypatch.setattr(detector, "detect", lambda tr, img, db, p: fake)
    argv = ["--trace", str(ROOT / "traces" / "synth" / "f2-violation.jsonl.gz"), "--root", str(ROOT)]

    assert cli.main(argv) == 1
    assert "판정 로그" not in capsys.readouterr().out

    assert cli.main([*argv, "--verbose"]) == 1
    out = capsys.readouterr().out
    assert "판정 로그 (체크포인트 2개)" in out
    assert "과거 0 + 미래 0 = 0  -" in out
    assert "과거 1 + 미래 16 = 17  ROP" in out
    assert out.index("판정 로그") < out.index("실행 스텝")  # 방어자 판정 다음에 실행 결과


def test_unreadable_trace_is_error(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text("not json\n", encoding="utf-8")
    assert cli.main(["--trace", str(path)]) == 2


def test_detection_on_fake_modules_is_error(tmp_path):
    """모듈 파일이 없거나(sha256 가짜) 아직 미구현이면 판정하지 않고 종료 코드 2."""
    path = tmp_path / "t.log"
    trace_io.dump(tiny_trace(), path)
    assert cli.main(["--trace", str(path), "--root", str(tmp_path)]) == 2
