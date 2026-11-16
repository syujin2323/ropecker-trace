"""future 레인 계약 예시: W=8192면 최근 코드 페이지 2개(LRU)."""

from ropecker.window import Window


def test_window_two_pages_lru():
    w = Window(8192)
    assert w.enter(0x401000) is True  # 빈 윈도 → 검사
    assert w.enter(0x401010) is False  # 같은 페이지
    assert w.enter(0x402000) is True  # 두 번째 페이지 진입
    assert w.enter(0x401020) is False  # 아직 윈도 안(페이지 0x401이 가장 최근)
    assert w.enter(0x7F0000) is True  # 세 번째 페이지 → 가장 오래 안 쓴 0x402 페이지를 뺌
    assert w.enter(0x402000) is True  # 빠졌으므로 다시 검사
