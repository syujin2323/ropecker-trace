"""보호 적용 전·후 비교 실행기 (12주차 활동 4·5, 13주차 활동 2·3).

동결 사례(cases/frozen.json)의 트레이스마다 README의 한 줄 명령을 두 번 실행한다.
  보호 적용 전: python -m ropecker --trace <트레이스> --window W --threshold T --cmp C --no-check
  보호 적용 후: python -m ropecker --trace <트레이스> --window W --threshold T --cmp C --verbose
콘솔 출력은 runs/<check id>-<synth|real>.<before|after>.log, 결과 JSON은 같은 이름의 .json에 남기고,
비교표를 compare.md로 만든다. 표의 '일치'는 tests/test_frozen.py와 같은 기준(ropecker.cases.judge)이다.

    uv run python scripts/run_cases.py              # 결과: results/w12/
    uv run python scripts/run_cases.py --out DIR

종료 코드: 0 = 기대와 다른 사례 없음(미구현은 허용), 1 = 불일치나 오류가 있음.

--cases를 주면 13주차 추가 사례(cases/extra/*.json, 형식은 cases/extra/README.md)를 같은 방식으로 돌린다.
트레이스 check는 전·후 두 번, 단위 check(pytest)는 한 번 실행하고, 기대와 다른 결과를 반례 목록(C1…)으로 모은다.

    uv run python scripts/run_cases.py --cases cases/extra                 # 전체 → results/w13/ (커밋)
    uv run python scripts/run_cases.py --cases cases/extra --only E2       # 일부 → results/w13-only.tmp/ (커밋 안 함)
    uv run python scripts/run_cases.py --cases cases/extra --only E2 --out results/w13/E2-before-fix

추가 사례에서 기대와 다른 결과는 찾아낸 반례이지 실행 실패가 아니다.
종료 코드(--cases): 0 = 오류 없음(반례 포함), 1 = ⚠️ 오류가 있음, 2 = 사례 파일 형식 오류·없는 사례 번호.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # `python scripts/run_cases.py`로 실행해도 ropecker를 찾게 한다

from ropecker.cases import TRACE_KINDS, describe_expect, iter_checks, judge, load_frozen, trace_path  # noqa: E402

DEFAULT_OUT = Path("results") / "w12"
EXTRA_OUT = Path("results") / "w13"
ONLY_OUT = Path("results") / "w13-only.tmp"  # --only(일부 실행)의 기본 결과 폴더, .gitignore의 results/*.tmp/
KIND_NAMES = {"synth": "합성", "real": "실제 수집"}
EXECVE_END = "syscall:59"  # 위반 트레이스의 피해: execve 도달 = 셸 실행


def _rel(path: Path, start: Path = ROOT) -> str:
    """둘 다 저장소 안이면 start 기준 상대 경로('/' 구분), 아니면 절대 경로."""
    path, start = path.resolve(), start.resolve()
    if path.is_relative_to(ROOT) and start.is_relative_to(ROOT):
        return Path(os.path.relpath(path, start)).as_posix()
    return path.as_posix()


def run_cli(trace: Path, params: dict, mode: str, runs: Path, name: str, extra_args: list[str] | None = None) -> dict:
    """CLI를 별도 프로세스로 한 번 실행하고 콘솔 출력(.log)과 결과 JSON(.json)을 남긴다.

    extra_args는 추가 사례의 args(예: ["--align-check"])로, --json 앞에 붙는다.
    """
    json_path = runs / f"{name}.{mode}.json"
    log_path = runs / f"{name}.{mode}.log"
    json_path.unlink(missing_ok=True)  # 지난 실행의 JSON이 이번 결과로 오인되지 않게
    args = ["--trace", trace.as_posix(), "--window", str(params["window"])]
    args += ["--threshold", str(params["threshold"]), "--cmp", params["cmp"]]
    args += ["--no-check"] if mode == "before" else ["--verbose"]
    args += list(extra_args or [])
    args += ["--json", _rel(json_path)]
    proc = subprocess.run(
        [sys.executable, "-m", "ropecker", *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
        check=False,
    )
    command = " ".join(["python -m ropecker", *args])
    log_path.write_text(
        f"$ {command}\n{proc.stdout}{proc.stderr}[종료 코드 {proc.returncode}]\n",
        encoding="utf-8",
        newline="\n",
    )
    result = None
    if json_path.exists():
        with open(json_path, encoding="utf-8") as f:
            result = json.load(f)
    return {"code": proc.returncode, "stderr": proc.stderr, "result": result, "log": log_path}


def describe_before(run: dict) -> str:
    r = run["result"]
    if run["code"] != 0 or r is None:
        return "오류 (로그 참고)"
    text = f"{r['steps']:,}스텝, 끝 {r['trace_end']}"
    if r["trace_end"] == EXECVE_END:
        text += " (execve 도달 = 셸 실행)"
    elif r["trace_end"] == "exit:0":
        text += " (정상 종료)"
    return text


def describe_after(run: dict, before: dict) -> str:
    r = run["result"]
    if r is None:
        m = re.search(r"미구현: ([^:\s]+)", run["stderr"])
        return f"미구현 ({m.group(1)})" if m else "오류 (로그 참고)"
    text = f"{r['verdict']}, 연쇄 {r['chain_len']}"
    cp = r.get("checkpoint")
    if r["verdict"] == "ROP" and cp:
        text += f", 스텝 {cp['step']}에서 중단"
        b = before["result"]
        if b and b["trace_end"] == EXECVE_END:
            text += " (execve 전, 피해 제거)" if cp["step"] < b["steps"] - 1 else " (execve 뒤, 피해 발생)"
    return text


def status(exp: dict, run: dict) -> tuple[str, bool]:
    """(표에 쓸 일치 여부, 실패인가). 미구현은 실패가 아니다(12주차 stub 허용)."""
    if run["result"] is None:
        if "미구현:" in run["stderr"]:
            return "⏳ 미구현", False
        return "⚠️ 오류", True
    problems = judge(exp, run["result"])
    if problems:
        return "❌ 불일치: " + "; ".join(problems), True
    return "✅ 일치", False


def _cell(text) -> str:
    """Markdown 표 칸 하나로 쓸 수 있게(| 와 줄바꿈을 바꾼다)."""
    return str(text).replace("|", "\\|").replace("\n", " ")


def _cond(params: dict, base: dict, args: list[str]) -> str:
    """기본 파라미터와 다른 실행 조건만 짧게 적는다."""
    out = []
    if params["window"] != base["window"]:
        out.append(f"W={params['window']}")
    if params["threshold"] != base["threshold"]:
        out.append(f"T={params['threshold']}")
    if params["cmp"] != base["cmp"]:
        out.append("판정 연쇄 > T" if params["cmp"] == "gt" else "판정 연쇄 ≥ T")
    if args:
        out.append("`" + " ".join(args) + "`")
    return ", ".join(out)


def junit_counts(xml_text: str) -> dict:
    """pytest --junitxml 결과에서 tests·failures·errors·skipped 수를 센다."""
    root = ET.fromstring(xml_text)
    suites = [root] if root.tag == "testsuite" else root.findall("testsuite")
    return {k: sum(int(s.get(k, 0)) for s in suites) for k in ("tests", "failures", "errors", "skipped")}


def unit_status(counts: dict | None, want_pass: bool) -> tuple[str, str, list[str]]:
    """(실행 결과 글, 표시, 기대와 다른 점). skip·준비 오류·테스트 없음은 판정하지 않고 ⚠️로 둔다."""
    if counts is None:
        return "오류 (로그 참고)", "⚠️ 오류", []
    if counts["tests"] == 0:
        return "테스트 없음", "⚠️ 오류", ["테스트를 찾지 못함"]
    if counts["errors"]:
        return f"준비 오류 {counts['errors']}개", "⚠️ 오류", ["테스트 준비 중 오류(로그 참고)"]
    if counts["skipped"]:
        return f"skip {counts['skipped']}개", "⚠️ 오류", ["skip된 테스트는 판정하지 않음"]
    got = "통과" if counts["failures"] == 0 else "실패"
    want = "통과" if want_pass else "실패"
    problems = [] if got == want else [f"테스트 {got} (기대 {want})"]
    return f"테스트 {got}", ("❌ 기대와 다름" if problems else "✅ 기대와 같음"), problems


def run_pytest(node: str, runs: Path, name: str) -> dict:
    """추가 사례의 단위 check: pytest 노드 하나를 별도 프로세스로 돌리고 로그를 남긴다.

    xfail 표시는 무시하고(--runxfail) 실제 통과·실패로 센다. junit 파일은 임시 폴더에 두어 결과 폴더가
    실행할 때마다 바뀌지 않게 한다.
    """
    log_path = runs / f"{name}.pytest.log"
    with tempfile.TemporaryDirectory() as tmp:
        xml_path = Path(tmp) / "junit.xml"
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", node, "-q", "-rA", "--runxfail", "-p", "no:cacheprovider",
             f"--junitxml={xml_path}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            env={**os.environ, "PYTHONUTF8": "1", "PYTHONIOENCODING": "utf-8"},
            check=False,
        )
        counts = junit_counts(xml_path.read_text(encoding="utf-8")) if xml_path.exists() else None
    log_path.write_text(
        f"$ python -m pytest {node} -q -rA --runxfail\n{proc.stdout}{proc.stderr}[종료 코드 {proc.returncode}]\n",
        encoding="utf-8",
        newline="\n",
    )
    return {"code": proc.returncode, "log": log_path, "counts": counts}


def _extra_check(case: dict, chk: dict, base: dict, runs: Path, out: Path, synth_hint: str) -> dict:
    """추가 사례 check 하나를 실행해 표 한 행에 쓸 값을 돌려준다."""
    from ropecker.extra import params_for, same_spec, trace_header, trace_of

    name, exp = chk["id"], chk["expect"]
    if "pytest" in chk:
        run = run_pytest(chk["pytest"], runs, name)
        after, mark, problems = unit_status(run["counts"], exp["pass"])
        row = {"cond": f"단위 테스트 `{chk['pytest']}`", "before": "—", "expect": f"테스트 {'통과' if exp['pass'] else '실패'}"}
        return {**row, "after": after, "mark": mark, "problems": problems, "evidence": [f"[로그]({_rel(run['log'], out)})"]}

    trace = trace_of(chk)
    params = params_for(base, case, chk)
    args = chk.get("args", [])
    cond = f"{'합성' if 'synth' in chk else '수집'} `{name}`"
    if extra := _cond(params, base, args):
        cond += f" ({extra})"
    row = {"cond": cond, "expect": describe_expect(exp)}
    gen = f"`python -m ropecker.synth --extra{synth_hint} --only {case['id']}`"
    if not (ROOT / trace).exists():
        hint = gen if "synth" in chk else "수집 전"
        return {**row, "before": "—", "after": "—", "mark": f"⏳ 트레이스 없음({hint})", "problems": [], "evidence": []}
    if "synth" in chk:
        again = f"{gen[:-1]} --force`"
        try:
            current = same_spec(trace_header(ROOT / trace).get("spec"), chk["synth"])
        except ValueError as e:
            return {**row, "before": "—", "after": "—", "mark": f"⚠️ {e} — {again}로 다시 만드세요", "problems": [],
                    "evidence": []}
        if not current:
            stale = f"⚠️ 스펙과 다른 옛 트레이스(스펙을 되돌리거나 {again}로 다시 만드세요)"
            return {**row, "before": "—", "after": "—", "mark": stale, "problems": [], "evidence": []}
    before = run_cli(trace, params, "before", runs, name, args)
    after = run_cli(trace, params, "after", runs, name, args)
    row["before"] = describe_before(before)
    row["after"] = describe_after(after, before)
    row["evidence"] = [
        f"[전]({_rel(before['log'], out)})",
        f"[후]({_rel(after['log'], out)})",
        f"[트레이스]({_rel(ROOT / trace, out)})",
    ]
    if after["result"] is None:
        return {**row, "mark": "⚠️ 오류", "problems": []}
    problems = judge(exp, after["result"])
    return {**row, "mark": "❌ 기대와 다름" if problems else "✅ 기대와 같음", "problems": problems}


def run_extra(cases_path: Path, out: Path, only: set[str] | None) -> int:
    """13주차 추가 사례를 실행해 out/compare.md(사례 표 + 반례 목록)를 만든다."""
    from ropecker.extra import analysis_for, load_cases

    try:
        cases = load_cases(cases_path, ROOT)
    except ValueError as e:
        print(f"사례 파일 오류: {e}", file=sys.stderr)
        return 2
    if only:
        unknown = only - {c["id"] for c in cases}
        if unknown:
            print(f"없는 사례 번호: {sorted(unknown)}", file=sys.stderr)
            return 2
        cases = [c for c in cases if c["id"] in only]
    base = load_frozen(ROOT)["params"]
    runs = out / "runs"
    runs.mkdir(parents=True, exist_ok=True)

    rows, cex = [], []
    counts = {"✅": 0, "❌": 0, "⏳": 0, "⚠️": 0}
    rel_cases = _rel(Path(cases_path).resolve())
    synth_hint = "" if rel_cases == "cases/extra" else f" --cases {rel_cases}"
    for case in cases:
        for chk in case["checks"]:
            r = _extra_check(case, chk, base, runs, out, synth_hint)
            counts[r["mark"].split()[0]] += 1
            result = r["mark"] + (": " + "; ".join(r["problems"]) if r["problems"] else "")
            rows.append(
                [f"{case['id']} {case['제목']}", case["방향"], case["구분"], r["cond"], r["before"], r["after"],
                 r["expect"], result, " · ".join(r["evidence"])]
            )
            if r["mark"].startswith("❌"):
                a = analysis_for(case, chk)
                cex.append(
                    [f"C{len(cex) + 1}", f"{case['id']} `{chk['id']}`: {case['입력']}", case["기대 결과"],
                     f"{r['after']} — {'; '.join(r['problems'])}", a.get("분류", "분류 전"), a.get("처리", "—"),
                     a.get("근거", "—")]
                )

    op = "≥" if base["cmp"] == "ge" else ">"
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
    head = [
        "# 추가 검증 사례 실행 결과 (13주차)",
        "",
        f"> `uv run python scripts/run_cases.py --cases {rel_cases}`가 만든 파일입니다. 직접 고치지 말고 다시 실행하세요.",
        "",
        f"- 실행: {now}, {platform.platform()}, Python {platform.python_version()}",
        f"- 기본 파라미터: W={base['window']}, T={base['threshold']}, 판정 연쇄 {op} T (사례마다 다른 조건은 '트레이스·조건' 열)",
        "- 보호 적용 전: `--no-check`, 보호 적용 후: 기본 실행 + `--verbose`. 기대 결과는 사례 파일에 실행 전에 적은 값이다.",
        f"- 결과: 기대와 같음 {counts['✅']} · 기대와 다름(반례) {counts['❌']} · 실행 전 {counts['⏳']} · 오류 {counts['⚠️']}",
    ]
    if only:
        head.append(f"- 일부만 실행: {', '.join(sorted(only, key=lambda s: int(s[1:])))} (`--only`)")
    head.append("")
    table = [
        "## 추가 검증 사례",
        "",
        "| 사례 | 방향 | 구분 | 트레이스·조건 | 보호 적용 전 | 보호 적용 후 | 기대 결과 | 결과 | 증거 |",
        "|---|---|---|---|---|---|---|---|---|",
        *("| " + " | ".join(_cell(c) for c in r) + " |" for r in rows),
    ]
    if not rows:
        table.append("| (사례 없음) | | | | | | | | |")
    cex_part = ["", "## 반례 목록", ""]
    if cex:
        cex_part += [
            "| 번호 | 입력 | 기대 결과 | 실제 결과 | 분류 | 처리 | 판단 근거 |",
            "|---|---|---|---|---|---|---|",
            *("| " + " | ".join(_cell(c) for c in r) + " |" for r in cex),
        ]
    else:
        cex_part.append("기대와 다른 결과가 없다(시험한 입력과 결과는 위 표).")
    notes = [
        "",
        "- 분류·처리·판단 근거는 사례 파일의 \"결과 분석\"에 적은 값이다"
        "(13주차 자료 9쪽: 구현 버그 / 명세상 미지원 / 원논문 한계). 비어 있으면 \"분류 전\".",
        "- 기대와 다른 결과는 기대값을 바꾸지 않고 원인 분석으로 잇는다. 구현 버그를 고치면 같은 입력으로 다시 실행해 전·후를 남긴다.",
    ]
    (out / "compare.md").write_text("\n".join(head + table + cex_part + notes) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(head[4:] + table + cex_part))
    print(f"\n결과: {_rel(out / 'compare.md')}, 실행 로그: {_rel(runs)}/")
    return 1 if counts["⚠️"] else 0


def extra_out(out: Path | None, only: set[str] | None) -> Path:
    """--cases의 결과 폴더: --out이 있으면 그것, --only(일부 실행)면 커밋하지 않는 폴더, 아니면 results/w13.

    일부 실행이 공용 results/w13/compare.md를 덮어 팀원끼리 충돌하지 않게 한다.
    """
    if out is not None:
        return out
    return ROOT / (ONLY_OUT if only else EXTRA_OUT)


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows 콘솔에서도 한글이 깨지지 않게
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(description="동결 사례(기본) 또는 13주차 추가 사례를 보호 적용 전·후로 실행해 비교표를 만든다.")
    ap.add_argument("--out", type=Path, help="결과 폴더 (기본 results/w12, --cases면 results/w13, --only면 results/w13-only.tmp)")
    ap.add_argument("--cases", help="13주차 추가 사례 파일·폴더, 현재 폴더 기준 (예: cases/extra). 없으면 동결 사례를 실행")
    ap.add_argument("--only", help="--cases에서 실행할 사례 번호, 쉼표로 구분 (예: E2,E7)")
    args = ap.parse_args(argv)
    if args.cases:
        only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
        out = extra_out(args.out, only)
        if only and not args.out:
            print(f"일부만 실행(--only) → {_rel(out)}/ (커밋하지 않음). results/w13/은 --only 없이 전체를 실행해 갱신합니다.")
        return run_extra(Path(args.cases).resolve(), out, only)
    if args.only:
        ap.error("--only는 --cases와 함께 씁니다")
    return run_frozen(args.out or ROOT / DEFAULT_OUT)


def run_frozen(out: Path) -> int:
    """동결 사례(cases/frozen.json)를 실행해 out/compare.md를 만든다(12주차)."""
    runs = out / "runs"
    runs.mkdir(parents=True, exist_ok=True)

    data = load_frozen(ROOT)
    params = data["params"]
    rows, counts, failed = [], {"✅": 0, "❌": 0, "⏳": 0, "⚠️": 0}, False
    for case, chk in iter_checks(data):
        for kind in TRACE_KINDS:
            trace = trace_path(chk["id"], kind)
            if not (ROOT / trace).exists():
                continue
            name = f"{chk['id']}-{kind}"
            before = run_cli(trace, params, "before", runs, name)
            after = run_cli(trace, params, "after", runs, name)
            mark, bad = status(chk["expect"], after)
            counts[mark.split()[0]] += 1
            failed |= bad
            evidence = [f"[전]({_rel(before['log'], out)})", f"[후]({_rel(after['log'], out)})"]
            stdout_txt = ROOT / "traces" / kind / f"{chk['id']}.stdout.txt"
            if stdout_txt.exists():
                evidence.append(f"[프로그램 출력]({_rel(stdout_txt, out)})")
            rows.append(
                [
                    case["구분"],
                    f"{KIND_NAMES[kind]} `{chk['id']}`",
                    describe_before(before),
                    describe_after(after, before),
                    describe_expect(chk["expect"]),
                    mark,
                    " · ".join(evidence),
                ]
            )

    op = "≥" if params["cmp"] == "ge" else ">"
    now = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %z")
    head = [
        "# 보호 적용 전·후 비교 (12주차)",
        "",
        "> `uv run python scripts/run_cases.py`가 만든 파일입니다. 직접 고치지 말고 다시 실행하세요.",
        "",
        f"- 실행: {now}, {platform.platform()}, Python {platform.python_version()}",
        f"- 동결 사례 파라미터: W={params['window']}, T={params['threshold']}, 판정 연쇄 {op} T",
        "- 보호 적용 전: `--no-check`(탐지 없이 실행 요약), 보호 적용 후: 기본 실행(탐지) + `--verbose`(판정 로그)",
        f"- 적용 후 판정: 일치 {counts['✅']} · 불일치 {counts['❌']} · 미구현 {counts['⏳']} · 오류 {counts['⚠️']}",
        "",
    ]
    table = [
        "| 사례 | 트레이스 | 보호 적용 전 (실행 결과) | 보호 적용 후 (방어자 판정) | 기대 결과 (동결) | 일치 | 증거 |",
        "|---|---|---|---|---|---|---|",
        *("| " + " | ".join(r) + " |" for r in rows),
    ]
    notes = [
        "",
        "- **보호 적용 전**은 탐지 없이 트레이스가 어떻게 끝났는지(공격자가 본 결과)이고, "
        "**보호 적용 후**는 방어자의 판정이다. 체크포인트별 판정 로그는 `runs/*.after.log`와 "
        "`runs/*.after.json`의 `checks`에 있다.",
        "- **미구현**은 그 레인이 아직 stub이라 판정하지 못한 경우다(12주차 지침상 허용, 사유는 보고서에 적는다).",
    ]
    (out / "compare.md").write_text("\n".join(head + table + notes) + "\n", encoding="utf-8", newline="\n")
    print("\n".join(head[4:8] + [""] + table))
    print(f"\n비교표: {_rel(out / 'compare.md')}, 실행 로그: {_rel(runs)}/")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
