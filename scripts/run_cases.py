"""보호 적용 전·후 비교 실행기 (12주차 활동 4·5).

동결 사례(cases/frozen.json)의 트레이스마다 README의 한 줄 명령을 두 번 실행한다.
  보호 적용 전: python -m ropecker --trace <트레이스> --window W --threshold T --cmp C --no-check
  보호 적용 후: python -m ropecker --trace <트레이스> --window W --threshold T --cmp C --verbose
콘솔 출력은 runs/<check id>-<synth|real>.<before|after>.log, 결과 JSON은 같은 이름의 .json에 남기고,
비교표를 compare.md로 만든다. 표의 '일치'는 tests/test_frozen.py와 같은 기준(ropecker.cases.judge)이다.

    uv run python scripts/run_cases.py              # 결과: results/w12/
    uv run python scripts/run_cases.py --out DIR

종료 코드: 0 = 기대와 다른 사례 없음(미구현은 허용), 1 = 불일치나 오류가 있음.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import subprocess
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))  # `python scripts/run_cases.py`로 실행해도 ropecker를 찾게 한다

from ropecker.cases import TRACE_KINDS, describe_expect, iter_checks, judge, load_frozen, trace_path  # noqa: E402

DEFAULT_OUT = Path("results") / "w12"
KIND_NAMES = {"synth": "합성", "real": "실제 수집"}
EXECVE_END = "syscall:59"  # 위반 트레이스의 피해: execve 도달 = 셸 실행


def _rel(path: Path, start: Path = ROOT) -> str:
    """둘 다 저장소 안이면 start 기준 상대 경로('/' 구분), 아니면 절대 경로."""
    path, start = path.resolve(), start.resolve()
    if path.is_relative_to(ROOT) and start.is_relative_to(ROOT):
        return Path(os.path.relpath(path, start)).as_posix()
    return path.as_posix()


def run_cli(trace: Path, params: dict, mode: str, runs: Path, name: str) -> dict:
    """CLI를 별도 프로세스로 한 번 실행하고 콘솔 출력(.log)과 결과 JSON(.json)을 남긴다."""
    json_path = runs / f"{name}.{mode}.json"
    log_path = runs / f"{name}.{mode}.log"
    json_path.unlink(missing_ok=True)  # 지난 실행의 JSON이 이번 결과로 오인되지 않게
    args = ["--trace", trace.as_posix(), "--window", str(params["window"])]
    args += ["--threshold", str(params["threshold"]), "--cmp", params["cmp"]]
    args += ["--no-check"] if mode == "before" else ["--verbose"]
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


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows 콘솔에서도 한글이 깨지지 않게
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(description="동결 사례를 보호 적용 전·후로 실행해 비교표를 만든다.")
    ap.add_argument("--out", type=Path, default=ROOT / DEFAULT_OUT, help="결과 폴더 (기본 results/w12)")
    args = ap.parse_args(argv)
    out: Path = args.out
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
