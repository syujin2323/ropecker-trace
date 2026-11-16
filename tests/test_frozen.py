"""11주차 동결 검증 사례(cases/frozen.json)를 그대로 실행한다.

- 사례 문구·기대값을 바꾸면 test_frozen_cases_unchanged가 실패한다(과목 고정 규칙).
- 트레이스: traces/synth/<check id>.jsonl.gz(기준, M0에서 생성)와 traces/real/<check id>.jsonl.gz(W12 수집).
  파일이 아직 없으면 skip, 분석 모듈이 미구현이면 xfail(conftest).
- 실제 트레이스 결과가 기대와 다르면 기대값을 고치지 말고 cases/extra에 반례로 기록한다.
"""

import hashlib
import json
from pathlib import Path

import pytest

from ropecker import trace as trace_io
from ropecker.model import Params

ROOT = Path(__file__).resolve().parents[1]
FROZEN = ROOT / "cases" / "frozen.json"
# 11/16 재제출본 기준. 재제출하지 않았다면 원문으로 되돌리고 이 값을 다시 계산한다.
FROZEN_SHA256 = "6feac7881ef92d450e67b60ad97a678edede395900cfa28ee203b41e87c2cdb9"


def _load() -> dict:
    with open(FROZEN, encoding="utf-8") as f:
        return json.load(f)


def _canonical_sha256(data: dict) -> str:
    return hashlib.sha256(json.dumps(data, ensure_ascii=False, sort_keys=True).encode("utf-8")).hexdigest()


def test_frozen_cases_unchanged():
    assert _canonical_sha256(_load()) == FROZEN_SHA256, "동결 사례가 바뀌었습니다(11주차 고정 규칙 위반)"


DATA = _load()
CHECKS = [(c, chk, kind) for c in DATA["cases"] for chk in c["checks"] for kind in ("synth", "real")]


@pytest.mark.parametrize(
    "case,check,kind", CHECKS, ids=[f"{chk['id']}-{kind}" for _, chk, kind in CHECKS]
)
def test_frozen_case(case, check, kind):
    path = ROOT / "traces" / kind / f"{check['id']}.jsonl.gz"
    if not path.exists():
        pytest.skip(f"트레이스 미생성: traces/{kind}/{path.name} (synth는 M0, real은 W12 수집)")

    from ropecker.detector import detect
    from ropecker.gadgetdb import GadgetDB
    from ropecker.image import Image

    p = DATA["params"]
    tr = trace_io.load(path)
    img = Image.from_header(tr.header, root=ROOT)
    db = GadgetDB.open(img, ROOT / "data" / "gadgets")
    res = detect(tr, img, db, Params(window=p["window"], threshold=p["threshold"], cmp=p["cmp"]))

    exp = check["expect"]
    assert res["verdict"] == exp["verdict"], f"{case['구분']}: {case['기대 결과']}"
    if "chain_len" in exp:
        assert res["chain_len"] == exp["chain_len"]
    if "chain_len_max" in exp:
        assert res["chain_len"] <= exp["chain_len_max"]
    if "chain_len_min" in exp:
        assert res["chain_len"] >= exp["chain_len_min"]
    if exp.get("gadgets_nonempty"):
        assert res["gadgets"], "연쇄를 이룬 gadget 주소가 출력되지 않음"
    if "trace_end" in exp:
        assert res["trace_end"] == exp["trace_end"]
