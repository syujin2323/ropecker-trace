import json

import pytest

from ropecker import cli
from ropecker import trace as trace_io
from tests.fakes import tiny_trace


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


def test_unreadable_trace_is_error(tmp_path):
    path = tmp_path / "bad.log"
    path.write_text("not json\n", encoding="utf-8")
    assert cli.main(["--trace", str(path)]) == 2


def test_detection_on_fake_modules_is_error(tmp_path):
    """모듈 파일이 없거나(sha256 가짜) 아직 미구현이면 판정하지 않고 종료 코드 2."""
    path = tmp_path / "t.log"
    trace_io.dump(tiny_trace(), path)
    assert cli.main(["--trace", str(path), "--root", str(tmp_path)]) == 2
