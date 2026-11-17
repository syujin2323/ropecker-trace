"""11주차 동결 검증 사례(cases/frozen.json)를 그대로 실행한다.

- 사례 문구·기대값을 바꾸면 test_frozen_cases_unchanged가 실패한다(과목 고정 규칙).
- 트레이스: traces/synth/<check id>.jsonl.gz(기준, M0에서 생성)와 traces/real/<check id>.jsonl.gz(W12 수집).
  파일이 아직 없으면 skip, 분석 모듈이 미구현이면 xfail(conftest).
- '기대와 일치' 기준은 ropecker/cases.py의 judge이고, scripts/run_cases.py 비교표도 같은 함수를 쓴다.
- 실제 트레이스 결과가 기대와 다르면 기대값을 고치지 말고 cases/extra에 반례로 기록한다.
"""

import hashlib
import json
from pathlib import Path

import pytest

from ropecker import trace as trace_io
from ropecker.cases import TRACE_KINDS, iter_checks, judge, load_frozen, trace_path
from ropecker.model import Params

ROOT = Path(__file__).resolve().parents[1]
# 11/16 재제출본 기준. 재제출하지 않았다면 원문으로 되돌리고 이 값을 다시 계산한다.
FROZEN_SHA256 = "6feac7881ef92d450e67b60ad97a678edede395900cfa28ee203b41e87c2cdb9"


def _canonical_sha256(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def test_frozen_cases_unchanged():
    assert _canonical_sha256(load_frozen(ROOT)) == FROZEN_SHA256, (
        "동결 사례가 바뀌었습니다(11주차 고정 규칙 위반)"
    )


DATA = load_frozen(ROOT)
CHECKS = [(c, chk, kind) for c, chk in iter_checks(DATA) for kind in TRACE_KINDS]


def _detect(path: Path) -> dict:
    from ropecker.detector import detect
    from ropecker.gadgetdb import GadgetDB
    from ropecker.image import Image

    p = DATA["params"]
    tr = trace_io.load(path)
    img = Image.from_header(tr.header, root=ROOT)
    db = GadgetDB.open(img, ROOT / "data" / "gadgets")
    return detect(tr, img, db, Params(window=p["window"], threshold=p["threshold"], cmp=p["cmp"]))


@pytest.mark.parametrize("case,check,kind", CHECKS, ids=[f"{chk['id']}-{kind}" for _, chk, kind in CHECKS])
def test_frozen_case(case, check, kind):
    path = ROOT / trace_path(check["id"], kind)
    if not path.exists():
        pytest.skip(f"트레이스 미생성: traces/{kind}/{path.name} (synth는 M0, real은 W12 수집)")

    problems = judge(check["expect"], _detect(path))
    assert not problems, f"{case['구분']}: {case['기대 결과']} → {problems}"


SYNTH_IDS = [chk["id"] for _, chk in iter_checks(DATA)]


@pytest.mark.parametrize("check_id", SYNTH_IDS)
def test_result_log_contract(check_id):
    """방어자 판정 로그(checks)가 결과 요약 값과 맞는지 확인한다(docs/design.md 5절)."""
    res = _detect(ROOT / trace_path(check_id, "synth"))
    checks = res["checks"]
    assert res["n_checkpoints"] == len(checks)
    steps = [c["step"] for c in checks]
    assert steps == sorted(set(steps)), "체크포인트는 스텝 순서로 한 번씩"
    for c in checks:
        assert {"step", "pc", "reason", "past", "future", "total"} <= set(c)
        assert c["total"] == c["past"] + c["future"]
    if res["verdict"] == "ROP":
        last = checks[-1]
        assert (last["step"], last["total"]) == (res["checkpoint"]["step"], res["chain_len"])
    else:
        assert res["chain_len"] == max((c["total"] for c in checks), default=0)
