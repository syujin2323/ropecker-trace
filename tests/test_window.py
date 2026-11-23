"""future 레인 계약 예시: W=8192면 최근 코드 페이지 2개(LRU)."""

from ropecker.model import RISKY_SYSCALLS, Step, Trace
from ropecker.window import Window, checkpoints


def test_window_two_pages_lru():
    w = Window(8192)
    assert w.enter(0x401000) is True  # 빈 윈도 → 검사
    assert w.enter(0x401010) is False  # 같은 페이지
    assert w.enter(0x402000) is True  # 두 번째 페이지 진입
    assert w.enter(0x401020) is False  # 아직 윈도 안(페이지 0x401이 가장 최근)
    assert w.enter(0x7F0000) is True  # 세 번째 페이지 → 가장 오래 안 쓴 0x402 페이지를 뺌
    assert w.enter(0x402000) is True  # 빠졌으므로 다시 검사


def test_window_smaller_than_page_keeps_one_page():
    w = Window(100)
    assert w.enter(0x401000) is True
    assert w.enter(0x401FFF) is False
    assert w.enter(0x402000) is True
    assert w.enter(0x401000) is True


def _trace(steps):
    return Trace(header={}, steps=steps)


def test_checkpoints_window_and_risky_syscall():
    tr = _trace(
        [
            Step(0x401000),  # 0: 첫 페이지 → window
            Step(0x401004),  # 1: 같은 페이지
            Step(0x401008, sys=1),  # 2: 위험하지 않은 syscall(write) → 검사 아님
            Step(0x40100C, sys=59),  # 3: execve → syscall:59
            Step(0x7F0000, sys=10),  # 4: 윈도 밖 + mprotect → 한 번만, syscall 우선
            Step(0x7F0004),  # 5: 같은 페이지
        ]
    )
    assert list(checkpoints(tr, 8192, RISKY_SYSCALLS)) == [
        (0, "window"),
        (3, "syscall:59"),
        (4, "syscall:10"),
    ]
