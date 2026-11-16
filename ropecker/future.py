"""미래 연쇄 (레인: future). 논문 V-C의 Future Payload Detection.

체크포인트 스텝의 스냅샷(sp, stk)에서 출발한다. 현재 pc가 ret gadget이면 그 gadget의 sd로
스택에서 다음 주소를 읽고, 그 주소가 다시 gadget이면 adv만큼 sp를 옮겨 계속 따라간다.
jmp/call gadget, sd/adv가 None인 gadget, 스냅샷 범위를 벗어나는 읽기에서 멈춘다
(논문의 jmp 에뮬레이션은 생략 — 원논문과의 차이로 기록).
"""

from __future__ import annotations


def future_chain(pc: int, sp: int, stk: tuple[int, ...], db, max_len: int = 64) -> list[int]:
    """pc에서 시작해 앞으로 이어질 gadget 주소들(pc 자신이 gadget이면 첫 항목)."""
    raise NotImplementedError("future.future_chain: future 레인(W12)")
