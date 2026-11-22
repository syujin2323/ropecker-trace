"""통합 판정 (레인: past·infra).

체크포인트마다 과거 연쇄(lbr → past)와 미래 연쇄(future)를 구해 합산하고,
Params.is_rop(합)이면 그 지점에서 ROP로 판정하고 멈춘다(논문: 프로세스 종료).
탐지가 없으면 '가장 긴 연쇄가 나온 체크포인트'의 값을 결과에 남긴다.
결과 형식은 docs/design.md "결과 v1"(cli._print_summary가 이 키들을 읽는다).

12주차 임시 구현(stub): window·future 레인이 아직 NotImplementedError이면 입력 → 판정 → 출력 흐름을
먼저 잇기 위해 아래 대체 동작을 쓰고, 쓴 함수 이름을 결과의 `stubs`에 남긴다(design.md 5절).
  - window.checkpoints → _tmp_checkpoints: 같은 정의(LRU 페이지 W/4096개 + 위험 syscall)의 최소 구현
  - future.future_chain → 미래 연쇄 0(과거 연쇄만으로 판정)
해당 레인이 구현되면 코드 수정 없이 진짜 구현을 쓰고 `stubs`는 빈 목록이 된다.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator

from . import future as future_mod
from . import window as window_mod
from .lbr import branches, lbr_at
from .model import VERDICT_NORMAL, VERDICT_ROP, Params, Trace, hx
from .past import past_chain

PAGE = 4096


def _tmp_checkpoints(tr: Trace, size: int, risky: frozenset[int]) -> Iterator[tuple[int, str]]:
    """window.checkpoints 임시 구현(window 레인 구현 전까지만 쓴다)."""
    cap = max(1, size // PAGE)
    pages: OrderedDict[int, None] = OrderedDict()
    for i, st in enumerate(tr.steps):
        page = st.pc // PAGE
        miss = page not in pages
        if miss:
            pages[page] = None
            if len(pages) > cap:
                pages.popitem(last=False)
        else:
            pages.move_to_end(page)
        if st.sys is not None and st.sys in risky:
            yield i, f"syscall:{st.sys}"
        elif miss:
            yield i, "window"


def _checkpoints(tr: Trace, p: Params, stubs: list[str]) -> list[tuple[int, str]]:
    try:
        return list(window_mod.checkpoints(tr, p.window, p.risky_syscalls))
    except NotImplementedError:
        stubs.append("window.checkpoints")
        return list(_tmp_checkpoints(tr, p.window, p.risky_syscalls))


def _gadget_entries(img, past: list[int], fut: list[int]) -> list[dict]:
    out = []
    for src, addrs in (("past", past), ("future", fut)):
        for a in addrs:
            loc = img.locate(a)
            out.append(
                {
                    "addr": hx(a),
                    "module": loc[0] if loc else None,
                    "off": hx(loc[1]) if loc else None,
                    "from": src,
                }
            )
    return out


def detect(tr: Trace, img, db, p: Params) -> dict:
    from .cli import unchecked_result  # 실행 요약 키(steps·trace_end·params 등)를 한곳에서 만든다

    stubs: list[str] = []
    brs = branches(tr, img)
    future_ok = True

    checks: list[dict] = []
    chains: list[tuple[list[int], list[int]]] = []  # checks와 같은 순서의 (과거, 미래) gadget 주소
    rop = False
    for step, reason in _checkpoints(tr, p, stubs):
        st = tr.steps[step]
        past, unaligned = past_chain(lbr_at(brs, step, p.lbr_depth), db, p.align_check)

        fut: list[int] = []
        if not unaligned and future_ok and st.sp is not None and st.stk is not None:
            try:
                fut = future_mod.future_chain(st.pc, st.sp, st.stk, db)
            except NotImplementedError:
                future_ok = False
                stubs.append("future.future_chain")
            if p.align_check:
                for i, a in enumerate(fut):
                    g = db.at(a)
                    if g is not None and not g.aligned:
                        fut, unaligned = fut[: i + 1], True
                        break

        total = len(past) + len(fut)
        checks.append(
            {
                "step": step,
                "pc": hx(st.pc),
                "reason": reason,
                "past": len(past),
                "future": len(fut),
                "total": total,
            }
        )
        chains.append((past, fut))
        if unaligned or p.is_rop(total):
            rop = True
            break  # 처음 ROP가 나온 체크포인트에서 멈춘다

    res = unchecked_result(tr, p)
    res["verdict"] = VERDICT_ROP if rop else VERDICT_NORMAL
    if checks:
        if rop:
            k = len(checks) - 1
        else:
            k = max(range(len(checks)), key=lambda i: (checks[i]["total"], -i))  # 같으면 앞의 것
        c = checks[k]
        res.update(
            chain_len=c["total"],
            past_len=c["past"],
            future_len=c["future"],
            gadgets=_gadget_entries(img, *chains[k]),
            checkpoint={"step": c["step"], "pc": c["pc"], "reason": c["reason"]},
        )
    else:
        res.update(chain_len=0, past_len=0, future_len=0, gadgets=[], checkpoint=None)
    res["checks"] = checks
    res["n_checkpoints"] = len(checks)
    res["stubs"] = stubs
    return res
