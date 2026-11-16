"""sliding window와 검사 시점 (레인: future). 논문 V-B.

윈도는 최근에 실행한 코드 페이지 W/4096개(LRU)다. 윈도 밖 페이지의 명령을 실행하려는 순간이
검사 시점이고, 검사 후 그 페이지를 윈도에 넣는다(가장 오래된 페이지를 뺀다).
위험 시스템 콜(model.RISKY_SYSCALLS)을 부르는 스텝도 검사 시점이다.
"""

from __future__ import annotations

from collections.abc import Iterator

from .model import Trace

PAGE = 4096


class Window:
    def __init__(self, size: int) -> None:
        raise NotImplementedError("window.Window: future 레인(W12)")

    def enter(self, pc: int) -> bool:
        """pc가 윈도 밖이면 True를 돌려주고 윈도를 옮긴다. 안이면 False."""
        raise NotImplementedError("window.Window.enter")


def checkpoints(tr: Trace, size: int, risky: frozenset[int]) -> Iterator[tuple[int, str]]:
    """(스텝 번호, 이유) — 이유는 'window' 또는 'syscall:<번호>'."""
    raise NotImplementedError("window.checkpoints: future 레인(W12)")
