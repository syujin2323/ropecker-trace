"""sliding window와 검사 시점 (레인: future). 논문 V-B.

윈도는 최근에 실행한 코드 페이지 W/4096개(LRU)다. 윈도 밖 페이지의 명령을 실행하려는 순간이
검사 시점이고, 검사 후 그 페이지를 윈도에 넣는다(가장 오래된 페이지를 뺀다).
위험 시스템 콜(model.RISKY_SYSCALLS)을 부르는 스텝도 검사 시점이다.

원논문은 윈도 밖 페이지를 실행 불가로 표시해 page fault로 검사 시점을 잡는다. 여기서는 트레이스의
pc를 차례로 넣어 보며 같은 순간(윈도 밖 페이지 진입)을 찾는다.
"""

from __future__ import annotations

from collections import OrderedDict
from collections.abc import Iterator

from .model import Trace

PAGE = 4096


class Window:
    """최근 실행한 코드 페이지 size/4096개를 LRU로 들고 있는 윈도."""

    def __init__(self, size: int) -> None:
        if size <= 0:
            raise ValueError(f"윈도 크기는 양수여야 합니다: {size}")
        self.cap = max(1, size // PAGE)  # W가 4096보다 작아도 페이지 1개는 둔다
        self._pages: OrderedDict[int, None] = OrderedDict()  # 앞쪽이 가장 오래 안 쓴 페이지

    def enter(self, pc: int) -> bool:
        """pc가 윈도 밖이면 True를 돌려주고 윈도를 옮긴다. 안이면 False."""
        page = pc // PAGE
        if page in self._pages:
            self._pages.move_to_end(page)  # 최근 사용으로 갱신
            return False
        self._pages[page] = None
        if len(self._pages) > self.cap:
            self._pages.popitem(last=False)  # 가장 오래 안 쓴 페이지를 뺀다
        return True

    def pages(self) -> list[int]:
        """윈도 안 페이지 번호(오래된 것 → 최근 것). 디버깅·--verbose용."""
        return list(self._pages)


def checkpoints(tr: Trace, size: int, risky: frozenset[int]) -> Iterator[tuple[int, str]]:
    """(스텝 번호, 이유) — 이유는 'window' 또는 'syscall:<번호>'.

    한 스텝은 최대 한 번만 나온다. 윈도 밖 진입과 위험 syscall이 겹치면 syscall을 이유로 쓴다
    (프로세스에 더 위험한 쪽을 기록). 겹쳐도 윈도는 그 스텝의 페이지로 옮겨 둔다.
    """
    w = Window(size)
    for i, st in enumerate(tr.steps):
        miss = w.enter(st.pc)
        if st.sys is not None and st.sys in risky:
            yield i, f"syscall:{st.sys}"
        elif miss:
            yield i, "window"
