import pytest

from ropecker import trace as trace_io
from tests.fakes import tiny_trace


@pytest.mark.parametrize("name", ["t.log", "t.jsonl", "t.jsonl.gz"])
def test_roundtrip_plain_and_gzip(tmp_path, name):
    tr = tiny_trace()
    path = tmp_path / name
    trace_io.dump(tr, path)
    back = trace_io.load(path)
    assert back.header == tr.header
    assert back.steps == tr.steps
    assert back.end == tr.end


def test_validate_ok():
    assert trace_io.validate(tiny_trace()) == []


def test_validate_reports_problems():
    tr = tiny_trace()
    tr.header["modules"] = []
    tr.end = {"end": "weird"}
    errors = trace_io.validate(tr)
    assert any("modules" in e for e in errors)
    assert any("end" in e for e in errors)


def test_load_rejects_other_format(tmp_path):
    path = tmp_path / "x.jsonl"
    path.write_text('{"fmt": "nope", "v": 1}\n', encoding="utf-8")
    with pytest.raises(ValueError):
        trace_io.load(path)
