"""과거 연쇄 (레인: past). 논문 V-C의 Past Payload Detection.

LBR 항목을 최신부터 거꾸로 보면서 '목적지(dst)가 gadget'인 항목이 이어지는 동안 센다.
처음으로 조건이 깨지는 항목(gadget이 아닌 목적지)에서 멈춘다(논문 V-C).
LBR은 최근 16개(논문 II-B)라서 과거 연쇄는 최대 16이다. 현재 pc의 gadget은 마지막 항목의
목적지로 여기에 들어가고, 미래 연쇄(future.py)에는 들어가지 않는다.
"""

from __future__ import annotations

from .model import Branch


def past_chain(lbr: list[Branch], db, align_check: bool = False) -> tuple[list[int], bool]:
    """(연쇄를 이룬 gadget 주소들[오래된 것→최신], 비정렬 gadget을 만났는지).

    align_check가 켜져 있고 비정렬 gadget을 만나면 즉시 (지금까지 주소, True)를 돌려준다.
    """
    rev: list[int] = []  # 최신 → 오래된 순으로 모은 뒤 뒤집는다
    for br in reversed(lbr):
        g = db.at(br.dst)
        if g is None:
            break  # 처음으로 gadget이 아닌 목적지에서 멈춘다(V-C)
        rev.append(g.addr)
        if align_check and not g.aligned:
            return rev[::-1], True
    return rev[::-1], False
