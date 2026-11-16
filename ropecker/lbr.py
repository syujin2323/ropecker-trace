"""LBR 흉내 (레인: past).

트레이스의 pc 열에서 '실제로 일어난 간접 분기'만 골라 LBR 항목처럼 만든다.
스텝 i의 명령이 간접 분기(ret/jmp*/call*)이면 Branch(step=i, src=pc_i, dst=pc_{i+1}, kind)를 기록한다.
"""

from __future__ import annotations

from .model import Branch, Trace


def branches(tr: Trace, img) -> list[Branch]:
    """트레이스 전체의 간접 분기 목록(시간 순)."""
    raise NotImplementedError("lbr.branches: past 레인(W12)")


def lbr_at(brs: list[Branch], step: int, depth: int = 16) -> list[Branch]:
    """step *이전*에 일어난 간접 분기 중 최근 depth개(최신이 맨 뒤)."""
    raise NotImplementedError("lbr.lbr_at: past 레인(W12)")
