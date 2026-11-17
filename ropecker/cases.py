"""11주차 동결 검증 사례(cases/frozen.json) 읽기와 기대값 판정.

tests/test_frozen.py(자동 검사)와 scripts/run_cases.py(보호 적용 전·후 비교표)가
같은 기준으로 '기대와 일치'를 판단하도록 한 곳에 둔다. 기준은 docs/design.md 2절이다.
"""

from __future__ import annotations

import json
from pathlib import Path

FROZEN_PATH = Path("cases") / "frozen.json"
TRACE_KINDS = ("synth", "real")  # traces/<kind>/<check id>.jsonl.gz
EXPECT_KEYS = frozenset(
    {"verdict", "chain_len", "chain_len_min", "chain_len_max", "gadgets_nonempty", "trace_end"}
)


def load_frozen(root: str | Path = ".") -> dict:
    with open(Path(root) / FROZEN_PATH, encoding="utf-8") as f:
        return json.load(f)


def iter_checks(data: dict) -> list[tuple[dict, dict]]:
    """(사례, check) 쌍을 frozen.json 순서대로 돌려준다."""
    return [(case, chk) for case in data["cases"] for chk in case["checks"]]


def trace_path(check_id: str, kind: str) -> Path:
    """check id의 트레이스 파일(저장소 루트 기준 상대 경로)."""
    return Path("traces") / kind / f"{check_id}.jsonl.gz"


def _known(exp: dict) -> dict:
    unknown = set(exp) - EXPECT_KEYS
    if unknown:
        raise ValueError(f"frozen.json에 모르는 기대값 키: {sorted(unknown)}")
    return exp


def describe_expect(exp: dict) -> str:
    """기대값을 한 줄로 쓴다. 예: '정상, 연쇄 ≤ 10, 끝 exit:0'"""
    exp = _known(exp)
    parts = [exp["verdict"]]
    if "chain_len" in exp:
        parts.append(f"연쇄 = {exp['chain_len']}")
    if "chain_len_min" in exp:
        parts.append(f"연쇄 ≥ {exp['chain_len_min']}")
    if "chain_len_max" in exp:
        parts.append(f"연쇄 ≤ {exp['chain_len_max']}")
    if exp.get("gadgets_nonempty"):
        parts.append("gadget 주소 출력")
    if "trace_end" in exp:
        parts.append(f"끝 {exp['trace_end']}")
    return ", ".join(parts)


def judge(exp: dict, result: dict) -> list[str]:
    """결과 v1이 기대값과 다른 점을 모두 돌려준다. 빈 목록이면 기대와 일치한다."""
    exp = _known(exp)
    problems = []
    if result.get("verdict") != exp["verdict"]:
        problems.append(f"판정 {result.get('verdict')} (기대 {exp['verdict']})")
    n = result.get("chain_len")
    if "chain_len" in exp and n != exp["chain_len"]:
        problems.append(f"연쇄 {n} (기대 = {exp['chain_len']})")
    if "chain_len_min" in exp and (n is None or n < exp["chain_len_min"]):
        problems.append(f"연쇄 {n} (기대 ≥ {exp['chain_len_min']})")
    if "chain_len_max" in exp and (n is None or n > exp["chain_len_max"]):
        problems.append(f"연쇄 {n} (기대 ≤ {exp['chain_len_max']})")
    if exp.get("gadgets_nonempty") and not result.get("gadgets"):
        problems.append("연쇄를 이룬 gadget 주소가 출력되지 않음")
    if "trace_end" in exp and result.get("trace_end") != exp["trace_end"]:
        problems.append(f"끝 {result.get('trace_end')} (기대 {exp['trace_end']})")
    return problems
