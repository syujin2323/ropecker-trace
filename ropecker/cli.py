"""명령행 진입점.

    python -m ropecker --trace t.log --window 8192 --threshold 11          # 보호 적용 후(탐지)
    python -m ropecker --trace t.log --window 8192 --threshold 11 --no-check  # 보호 적용 전(요약만)

종료 코드: 0 정상(또는 미검사), 1 ROP, 2 오류·미구현.
"""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__
from . import trace as trace_io
from .model import (
    EXIT_ERROR,
    EXIT_NORMAL,
    EXIT_ROP,
    RESULT_FMT,
    RESULT_V,
    VERDICT_ROP,
    VERDICT_UNCHECKED,
    Params,
    Trace,
)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m ropecker",
        description="실행 트레이스에서 ROPecker 방식으로 gadget 연쇄를 세어 ROP 여부를 판정한다.",
    )
    p.add_argument("--trace", required=True, help="트레이스 v1 파일(JSON Lines, gzip 가능, 확장자 무관)")
    p.add_argument("--window", type=int, default=8192, help="sliding window 크기 W, 바이트 (기본 8192)")
    p.add_argument("--threshold", type=int, default=11, help="임계값 T (기본 11)")
    p.add_argument(
        "--cmp",
        choices=["ge", "gt"],
        default="ge",
        help="판정 비교: ge = 연쇄 ≥ T (기본, 11주차 보고서 기준), gt = 연쇄 > T (논문 기준)",
    )
    p.add_argument("--lbr-depth", type=int, default=16, help="과거 연쇄에 쓰는 LBR 깊이 (기본 16)")
    p.add_argument("--align-check", action="store_true", help="비정렬 gadget을 만나면 즉시 ROP로 판정")
    p.add_argument(
        "--no-check", action="store_true", help="탐지하지 않고 실행 요약만 출력 (보호 적용 전 비교용)"
    )
    p.add_argument("--db-dir", default="data/gadgets", help="gadget DB 폴더 (기본 data/gadgets)")
    p.add_argument("--root", default=".", help="트레이스 헤더의 모듈 경로를 찾을 기준 폴더 (기본 현재 폴더)")
    p.add_argument("--json", metavar="PATH", help="결과 JSON을 이 파일에도 저장")
    p.add_argument(
        "-v", "--verbose", action="store_true", help="체크포인트별 방어자 판정 로그(checks)도 출력"
    )
    p.add_argument("--version", action="version", version=f"ropecker-trace {__version__}")
    return p


def _utf8_stdio() -> None:
    """Windows 콘솔·파이프(cp949/cp1252)에서도 한글 출력이 깨지지 않게 UTF-8로 맞춘다."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


def _end_str(end: dict) -> str:
    kind = end.get("end", "max_steps")
    for key in ("code", "signal", "sys"):
        if key in end:
            return f"{kind}:{end[key]}"
    return kind


def unchecked_result(tr: Trace, params: Params) -> dict:
    """--no-check(보호 적용 전) 결과: 탐지 없이 실행 요약만 담는다."""
    return {
        "fmt": RESULT_FMT,
        "v": RESULT_V,
        "verdict": VERDICT_UNCHECKED,
        "chain_len": None,
        "past_len": None,
        "future_len": None,
        "gadgets": [],
        "checkpoint": None,
        "checks": [],
        "n_checkpoints": 0,
        "steps": len(tr.steps),
        "trace_end": _end_str(tr.end),
        "collector": tr.header.get("collector"),
        "params": params.as_json(),
        "stubs": [],
    }


def _print_checks(result: dict) -> None:
    """방어자 판정 로그: 체크포인트마다 과거·미래 연쇄와 합, 그 합이 ROP 기준을 넘는지."""
    checks = result.get("checks") or []
    p = result["params"]
    rule = Params(threshold=p["threshold"], cmp=p["cmp"])
    print(f"판정 로그 (체크포인트 {len(checks)}개)")
    for c in checks:
        mark = "ROP" if rule.is_rop(c["total"]) else "-"
        print(
            f"  스텝 {c['step']:>7}  pc {c['pc']}  {c['reason']:<10}  "
            f"과거 {c['past']} + 미래 {c['future']} = {c['total']}  {mark}"
        )


def _print_summary(result: dict, verbose: bool = False) -> None:
    verdict = result["verdict"]
    if verdict == VERDICT_UNCHECKED:
        print("판정: 미검사 (--no-check, 보호 적용 전)")
    else:
        p = result["params"]
        op = "≥" if p["cmp"] == "ge" else ">"
        print(
            f"판정: {verdict} (연쇄 길이 {result['chain_len']} = 과거 {result['past_len']} + "
            f"미래 {result['future_len']}, 기준 연쇄 {op} {p['threshold']})"
        )
        cp = result.get("checkpoint")
        if cp:
            print(f"체크포인트: 스텝 {cp['step']}, pc {cp['pc']}, 이유 {cp['reason']}")
        for g in result.get("gadgets", []):
            where = f"{g['module']}+{g['off']}" if g.get("module") else "?"
            print(f"  gadget {g['addr']} ({where}, {g.get('from', '?')})")
        if result.get("stubs"):
            print(
                f"임시 구현(stub) 사용: {', '.join(result['stubs'])} (해당 레인 구현 전, README '진행 현황')"
            )
        if verbose:
            _print_checks(result)
    print(f"실행 스텝 {result['steps']}, 트레이스 종료 {result['trace_end']}")


def main(argv: list[str] | None = None) -> int:
    _utf8_stdio()
    args = build_parser().parse_args(argv)
    params = Params(
        window=args.window,
        threshold=args.threshold,
        cmp=args.cmp,
        lbr_depth=args.lbr_depth,
        align_check=args.align_check,
        check=not args.no_check,
    )

    try:
        tr = trace_io.load(args.trace)
    except (OSError, ValueError) as e:
        print(f"오류: 트레이스를 읽지 못했습니다: {e}", file=sys.stderr)
        return EXIT_ERROR
    problems = trace_io.validate(tr)
    if problems:
        for msg in problems:
            print(f"오류: {msg}", file=sys.stderr)
        return EXIT_ERROR

    if not params.check:
        result = unchecked_result(tr, params)
    else:
        try:
            from .detector import detect
            from .gadgetdb import GadgetDB
            from .image import Image

            img = Image.from_header(tr.header, root=args.root)
            db = GadgetDB.open(img, args.db_dir)
            result = detect(tr, img, db, params)
        except NotImplementedError as e:
            print(f"미구현: {e} (README의 '진행 현황' 참고)", file=sys.stderr)
            return EXIT_ERROR
        except (OSError, ValueError) as e:
            print(f"오류: {e}", file=sys.stderr)
            return EXIT_ERROR

    _print_summary(result, verbose=args.verbose)
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(result, ensure_ascii=False, indent=2) + "\n")
    return EXIT_ROP if result["verdict"] == VERDICT_ROP else EXIT_NORMAL
