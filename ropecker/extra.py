"""13주차 추가 검증 사례(cases/extra/*.json) 읽기와 형식 검사.

사례 하나 = 파일 하나(`E<번호>-<짧은 이름>.json`)라서 팀원끼리 같은 파일을 고치지 않는다.
형식과 작성 요령은 cases/extra/README.md, 기대값(expect) 판정은 고정 사례와 같은 ropecker.cases.judge다.

  - 트레이스 check: `trace`(수집한 파일) 또는 `synth`(python -m ropecker.synth --extra로 만드는 스펙)
  - 단위 check: `pytest`(cases/extra/ 아래 테스트 하나), 기대는 {"pass": true}
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from .cases import EXPECT_KEYS

EXTRA_DIR = Path("cases") / "extra"
TRACE_DIR = Path("traces") / "extra"
DIRECTIONS = ("경계값", "표기 변형", "반복·동시", "자원 고갈", "상태 전이", "알려진 한계")  # 13주차 자료 7쪽
KINDS = ("정상", "위반", "경계")
CLASSES = ("구현 버그", "명세상 미지원", "원논문 한계", "반례 아님")  # 13주차 자료 9쪽 + 기대와 같음
REQUIRED = ("id", "제목", "담당", "방향", "구분", "입력", "기대 결과", "checks")
CASE_KEYS = frozenset(REQUIRED) | {"작성일", "근거", "params", "결과 분석", "메모"}
CHECK_KEYS = frozenset({"id", "trace", "synth", "pytest", "expect", "params", "args", "결과 분석", "메모"})
ANALYSIS_KEYS = frozenset({"분류", "근거", "처리", "실제 결과", "메모"})
INT_EXPECT_KEYS = ("chain_len", "chain_len_min", "chain_len_max", "past_len", "future_len", "detect_step_max")
PARAM_KEYS = frozenset({"window", "threshold", "cmp"})
RESERVED_ARGS = frozenset({"--trace", "--json", "--no-check", "--verbose", "-v", "--window", "--threshold", "--cmp"})
CASE_ID = re.compile(r"^E\d+$")
CHECK_ID = re.compile(r"^[a-z0-9][a-z0-9-]*$")

# 합성 스펙(synth) 문법 — 뜻은 cases/extra/README.md "합성 트레이스 스펙", 만드는 코드는 ropecker/synth.py
SYNTH_KEYS = frozenset({"chain", "ending", "stack_qwords"})
SYNTH_ENDINGS = ("execve", "stop", "none")
ENTRY_KINDS = ("pick", "addr", "nongadget")  # 체인 항목마다 정확히 하나
ENTRY_OPTS = frozenset({"page", "pops", "rsp_to", "sys", "메모"})
PICK_KEYS = frozenset({"asm", "kind", "aligned", "n", "n_min", "n_max", "module", "sd_known", "index"})
NONGADGET_KEYS = frozenset({"n_min", "n_max", "module", "index"})
PAGE_MODES = ("new", "same", "any")
SYNTH_MODULES = ("rop_vault", "libc.so.6")
GADGET_KINDS = ("ret", "jmp_ind", "call_ind")
ADDR_TEXT = re.compile(r"^(0x[0-9a-fA-F]+|(rop_vault|libc\.so\.6)\+0x[0-9a-fA-F]+)$")


def _reserved(args: list[str]) -> list[str]:
    """실행기가 붙이는 옵션과 겹치는 인자. '--threshold=12'와 줄임말('--thr')도 잡는다(argparse가 받아 줌)."""
    hits = []
    for a in args:
        if not a.startswith("-"):
            continue
        name = a.split("=", 1)[0]
        long_prefix = name.startswith("--") and len(name) > 2 and any(r.startswith(name) for r in RESERVED_ARGS)
        if name in RESERVED_ARGS or long_prefix:
            hits.append(a)
    return hits


def _is_num(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _addr_ok(v) -> bool:
    return (_is_num(v) and v >= 0) or (isinstance(v, str) and bool(ADDR_TEXT.match(v)))


def _entry_problems(e, where: str) -> list[str]:
    if not isinstance(e, dict):
        return [f"{where}: 체인 항목은 객체여야 합니다"]
    kinds = [k for k in ENTRY_KINDS if k in e]
    if len(kinds) != 1:
        return [f"{where}: 항목마다 {list(ENTRY_KINDS)} 중 정확히 하나를 씁니다"]
    kind = kinds[0]
    out = []
    unknown = set(e) - ENTRY_OPTS - {kind}
    if unknown:
        out.append(f"{where}: 모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(ENTRY_OPTS | {kind})})")
    if "page" in e and (kind == "addr" or e["page"] not in PAGE_MODES):
        out.append(f"{where}: page는 pick·nongadget에만 쓰고 값은 {list(PAGE_MODES)} 중 하나")
    if "pops" in e and (not isinstance(e["pops"], list) or not all(_addr_ok(v) for v in e["pops"])):
        out.append(f"{where}: pops는 값 목록 (정수 또는 \"0x…\")")
    if "rsp_to" in e and not _addr_ok(e["rsp_to"]):
        out.append(f"{where}: rsp_to는 주소 (정수 또는 \"0x…\")")
    if "sys" in e and (not _is_num(e["sys"]) or e["sys"] < 0):
        out.append(f"{where}: sys는 syscall 번호(정수)")
    body = e[kind]
    if kind == "addr":
        if not _addr_ok(body):
            out.append(f"{where}: addr는 \"0x…\" 또는 \"libc.so.6+0x…\"·\"rop_vault+0x…\"")
        return out
    allowed = PICK_KEYS if kind == "pick" else NONGADGET_KEYS
    if not isinstance(body, dict):
        return out + [f"{where}: {kind}는 조건 객체여야 합니다 (예: {{\"asm\": \"^ret$\"}})"]
    unknown = set(body) - allowed
    if unknown:
        out.append(f"{where}: {kind}에 모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(allowed)})")
    if body.get("module", "libc.so.6") not in SYNTH_MODULES:
        out.append(f"{where}: module은 {list(SYNTH_MODULES)} 중 하나")
    if "kind" in body and body["kind"] not in GADGET_KINDS:
        out.append(f"{where}: kind는 {list(GADGET_KINDS)} 중 하나")
    for key in ("n", "n_min", "n_max", "index"):
        if key in body and (not _is_num(body[key]) or body[key] < 0):
            out.append(f"{where}: {kind}.{key}는 0 이상의 정수")
    for key in ("aligned", "sd_known"):
        if key in body and not isinstance(body[key], bool):
            out.append(f"{where}: {kind}.{key}는 true 또는 false")
    if "asm" in body:
        try:
            re.compile(body["asm"])
        except (re.error, TypeError):
            out.append(f"{where}: {kind}.asm은 정규식 문자열 (예: \"^pop rdi; ret$\")")
    return out


def synth_problems(spec, where: str) -> list[str]:
    """합성 스펙의 형식 문제. 실제로 gadget을 고를 수 있는지는 만들 때(python -m ropecker.synth --extra) 확인한다."""
    if not isinstance(spec, dict):
        return [f"{where}: synth는 객체여야 합니다"]
    out = []
    unknown = set(spec) - SYNTH_KEYS
    if unknown:
        out.append(f"{where}: synth에 모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(SYNTH_KEYS)})")
    if spec.get("ending", "execve") not in SYNTH_ENDINGS:
        out.append(f"{where}: synth.ending은 {list(SYNTH_ENDINGS)} 중 하나")
    q = spec.get("stack_qwords", 32)
    if not _is_num(q) or not 1 <= q <= 512:
        out.append(f"{where}: synth.stack_qwords는 1~512 (수집기는 32)")
    chain = spec.get("chain")
    if not isinstance(chain, list) or not chain:
        return out + [f"{where}: synth.chain(체인 항목 목록)이 비어 있습니다"]
    for i, e in enumerate(chain):
        out += _entry_problems(e, f"{where} chain[{i}]")
    return out


def case_files(path: str | Path) -> list[Path]:
    """폴더면 그 안의 *.json(이름순), 파일이면 그 파일 하나."""
    p = Path(path)
    if p.is_dir():
        return sorted(p.glob("*.json"))
    return [p]


def _params_problems(params, where: str) -> list[str]:
    if not isinstance(params, dict):
        return [f"{where} params는 객체여야 합니다"]
    out = []
    unknown = set(params) - PARAM_KEYS
    if unknown:
        out.append(f"{where} params에 모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(PARAM_KEYS)})")
    if "cmp" in params and params["cmp"] not in ("ge", "gt"):
        out.append(f"{where} params.cmp는 'ge' 또는 'gt'")
    for key in ("window", "threshold"):
        if key in params and (not _is_num(params[key]) or params[key] <= 0):
            out.append(f"{where} params.{key}는 양의 정수")
    return out


def _analysis_problems(analysis, where: str) -> list[str]:
    if not isinstance(analysis, dict):
        return [f"{where} '결과 분석'은 객체여야 합니다"]
    out = []
    unknown = set(analysis) - ANALYSIS_KEYS
    if unknown:
        out.append(f"{where} '결과 분석'에 모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(ANALYSIS_KEYS)})")
    if "분류" in analysis and analysis["분류"] not in CLASSES:
        out.append(f"{where} 분류는 {list(CLASSES)} 중 하나")
    return out


def _check_problems(chk, case_id: str) -> list[str]:
    if not isinstance(chk, dict):
        return [f"{case_id}: check는 객체여야 합니다"]
    cid = chk.get("id", "")
    where = f"{case_id}/{cid or '?'}"
    out = []
    unknown = set(chk) - CHECK_KEYS
    if unknown:
        out.append(f"{where}: check에 모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(CHECK_KEYS)})")
    if not isinstance(cid, str) or not CHECK_ID.match(cid):
        out.append(f"{where}: check id는 영문 소문자·숫자·'-'만 (예: e2-loop-chain)")
    if "expect" not in chk or not isinstance(chk["expect"], dict):
        return out + [f"{where}: expect(실행 전에 적는 기대값)가 없습니다"]
    exp = chk["expect"]
    if "pytest" in chk:
        if "trace" in chk or "synth" in chk:
            out.append(f"{where}: pytest check에는 trace·synth를 함께 쓰지 않습니다")
        node = chk["pytest"]
        if not isinstance(node, str) or not node.replace("\\", "/").startswith(EXTRA_DIR.as_posix() + "/"):
            out.append(f"{where}: pytest는 {EXTRA_DIR.as_posix()}/ 아래 테스트여야 합니다 (예: cases/extra/unit/test_e3.py::test_x)")
        if set(exp) != {"pass"} or not isinstance(exp["pass"], bool):
            out.append(f"{where}: pytest check의 expect는 {{\"pass\": true}} 또는 {{\"pass\": false}}")
    else:
        if ("trace" in chk) == ("synth" in chk):
            out.append(f"{where}: trace(수집한 트레이스 경로)와 synth(합성 스펙) 중 정확히 하나를 씁니다")
        unknown = set(exp) - EXPECT_KEYS
        if unknown:
            out.append(f"{where}: 모르는 기대값 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(EXPECT_KEYS)})")
        if "verdict" not in exp or exp.get("verdict") not in ("정상", "ROP"):
            out.append(f"{where}: expect.verdict는 '정상' 또는 'ROP'")
        for key in INT_EXPECT_KEYS:
            if key in exp and (not _is_num(exp[key]) or exp[key] < 0):
                out.append(f"{where}: expect.{key}는 0 이상의 정수 (따옴표 없이, 예: 11)")
        if "gadgets_nonempty" in exp and not isinstance(exp["gadgets_nonempty"], bool):
            out.append(f"{where}: expect.gadgets_nonempty는 true 또는 false")
        if "trace_end" in exp and (not isinstance(exp["trace_end"], str) or not exp["trace_end"]):
            out.append(f"{where}: expect.trace_end는 문자열 (예: \"exit:0\", \"syscall:59\", \"max_steps\")")
        if "synth" in chk:
            out += synth_problems(chk["synth"], where)
        if "trace" in chk and (not isinstance(chk["trace"], str) or not chk["trace"].startswith("traces/")):
            out.append(f"{where}: trace는 저장소 루트 기준 경로 (예: traces/real/f3-boundary-11.jsonl.gz)")
        args = chk.get("args", [])
        if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            out.append(f"{where}: args는 문자열 목록 (예: [\"--align-check\"])")
        elif hits := _reserved(args):
            out.append(f"{where}: args에 {hits}는 쓰지 않습니다(실행기가 붙임, 줄임말·'=값' 형태 포함)")
    if "params" in chk:
        out += _params_problems(chk["params"], where)
    if "결과 분석" in chk:
        out += _analysis_problems(chk["결과 분석"], where)
    return out


def validate_case(case) -> list[str]:
    """사례 하나의 형식 문제를 모두 돌려준다. 빈 목록이면 통과."""
    if not isinstance(case, dict):
        return ["사례 파일의 최상위는 객체여야 합니다"]
    out = [f"필수 항목 '{k}'가 없습니다" for k in REQUIRED if k not in case]
    unknown = set(case) - CASE_KEYS - {"_file"}
    if unknown:
        out.append(f"모르는 키 {sorted(unknown)} (쓸 수 있는 키: {sorted(CASE_KEYS)})")
    if out:
        return out
    cid = case["id"]
    if not isinstance(cid, str) or not CASE_ID.match(cid):
        out.append(f"id는 E와 숫자 (예: E2), 지금 값 {cid!r}")
        cid = str(cid)
    for k in ("제목", "담당", "입력", "기대 결과"):
        if not isinstance(case[k], str) or not case[k].strip():
            out.append(f"{cid}: '{k}'를 적어 주세요")
    if case["방향"] not in DIRECTIONS:
        out.append(f"{cid}: 방향은 {list(DIRECTIONS)} 중 하나")
    if case["구분"] not in KINDS:
        out.append(f"{cid}: 구분은 {list(KINDS)} 중 하나")
    if "params" in case:
        out += _params_problems(case["params"], cid)
    if "결과 분석" in case:
        out += _analysis_problems(case["결과 분석"], cid)
    checks = case["checks"]
    if not isinstance(checks, list) or not checks:
        out.append(f"{cid}: checks가 비어 있습니다")
        return out
    for chk in checks:
        out += _check_problems(chk, cid)
    return out


def load_cases(path: str | Path = EXTRA_DIR, root: str | Path = ".") -> list[dict]:
    """사례 파일(또는 폴더 안 전부)을 읽고 검사해 사례 번호 순으로 돌려준다. 형식이 틀리면 ValueError.

    각 사례에는 읽은 파일 경로를 '_file'(root 기준)로 붙인다.
    """
    root = Path(root)
    p = Path(path)
    if not p.is_absolute():
        p = root / p
    if not p.exists():
        raise ValueError(f"사례 파일·폴더가 없습니다: {p.as_posix()}")
    cases: list[dict] = []
    case_where: dict[str, str] = {}
    check_where: dict[str, str] = {}
    for f in case_files(p):
        try:
            with open(f, encoding="utf-8") as fh:
                case = json.load(fh)
        except json.JSONDecodeError as e:
            raise ValueError(f"{f.name}: JSON 형식 오류 ({e})") from e
        problems = validate_case(case)
        if problems:
            raise ValueError(f"{f.name}: " + "; ".join(problems))
        if case["id"] in case_where:
            raise ValueError(f"{f.name}: 사례 번호 {case['id']}가 {case_where[case['id']]}와 겹칩니다")
        case_where[case["id"]] = f.name
        for chk in case["checks"]:
            if chk["id"] in check_where:
                raise ValueError(f"{f.name}: check id {chk['id']}가 {check_where[chk['id']]}와 겹칩니다")
            check_where[chk["id"]] = f.name
        try:
            case["_file"] = f.resolve().relative_to(root.resolve()).as_posix()
        except ValueError:
            case["_file"] = f.as_posix()
        cases.append(case)
    return sorted(cases, key=lambda c: int(c["id"][1:]))


def trace_header(path: str | Path) -> dict:
    """트레이스 파일의 헤더(첫 줄)만 읽는다. 합성 트레이스가 지금 스펙으로 만든 것인지 볼 때 쓴다."""
    from .trace import _open_text

    with _open_text(Path(path), "r") as f:
        return json.loads(f.readline())


def trace_of(chk: dict) -> Path:
    """트레이스 check의 트레이스 경로. trace가 없으면 synth로 만드는 traces/extra/<check id>.jsonl.gz."""
    if "trace" in chk:
        return Path(chk["trace"])
    return TRACE_DIR / f"{chk['id']}.jsonl.gz"


def params_for(base: dict, case: dict, chk: dict) -> dict:
    """고정 사례 파라미터 → 사례 params → check params 순으로 덮어쓴다."""
    return {**base, **case.get("params", {}), **chk.get("params", {})}


def analysis_for(case: dict, chk: dict) -> dict:
    """결과 분석: check에 있으면 그것, 없으면 사례의 것."""
    return chk.get("결과 분석") or case.get("결과 분석") or {}
