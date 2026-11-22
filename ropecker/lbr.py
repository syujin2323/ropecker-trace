"""LBR 흉내 (레인: past).

트레이스의 pc 열에서 '실제로 일어난 간접 분기'만 골라 LBR 항목처럼 만든다.
스텝 i의 명령이 간접 분기(ret/jmp*/call*)이면 Branch(step=i, src=pc_i, dst=pc_{i+1}, kind)를 기록한다.
"""

from __future__ import annotations

from bisect import bisect_left

from .model import INDIRECT_KINDS, Branch, Trace


def branches(tr: Trace, img) -> list[Branch]:
    """트레이스 전체의 간접 분기 목록(시간 순).

    직접 분기(jmp/jcc/call)는 LBR 필터에서 빼고, 마지막 스텝은 목적지(다음 pc)를 모르므로 기록하지 않는다.
    """
    steps = tr.steps
    out: list[Branch] = []
    for i in range(len(steps) - 1):
        pc = steps[i].pc
        kind = img.insn(pc).kind
        if kind in INDIRECT_KINDS:
            out.append(Branch(step=i, src=pc, dst=steps[i + 1].pc, kind=kind))
    return out


def lbr_at(brs: list[Branch], step: int, depth: int = 16) -> list[Branch]:
    """step *이전*에 일어난 간접 분기 중 최근 depth개(최신이 맨 뒤).

    brs는 branches()의 결과처럼 step 오름차순이어야 한다. 체크포인트 스텝 s의 pc로 들어온 분기는
    스텝 s-1에 기록되므로 여기에 포함된다(현재 gadget = 마지막 항목의 목적지).
    """
    if depth <= 0:
        return []
    hi = bisect_left(brs, step, key=lambda b: b.step)
    return brs[max(0, hi - depth) : hi]
