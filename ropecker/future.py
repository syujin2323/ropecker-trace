"""미래 연쇄 (레인: future). 논문 V-C의 Future Payload Detection.

체크포인트 스텝의 스냅샷(sp, stk)에서 출발한다. 현재 pc가 ret gadget이면 그 gadget의 sd로
스택에서 다음 주소를 읽고, 그 주소가 다시 gadget이면 adv만큼 sp를 옮겨 계속 따라간다.
jmp/call gadget, sd/adv가 None인 gadget, 스냅샷 범위를 벗어나는 읽기, gadget이 아닌 주소에서 멈춘다
(논문의 jmp 에뮬레이션은 생략 — 원논문과의 차이로 기록).

현재 pc의 gadget은 과거 연쇄(마지막 LBR 항목의 목적지)에 이미 들어가므로 여기서는 세지 않는다.
연쇄 길이 = len(past) + len(future).

stk는 sp부터 위로 읽은 qword 목록이다: stk[k]는 주소 sp + 8*k의 값.
"""

from __future__ import annotations

QWORD = 8


def _read(sp0: int, stk: tuple[int, ...], addr: int) -> int | None:
    """스냅샷에서 addr의 qword를 읽는다. 범위 밖이거나 8바이트 경계가 아니면 None."""
    off = addr - sp0
    if off < 0 or off % QWORD:
        return None
    k = off // QWORD
    if k >= len(stk):
        return None
    return stk[k]


def future_chain(pc: int, sp: int, stk: tuple[int, ...], db, max_len: int = 64) -> list[int]:
    """pc의 gadget *다음*에 이어질 gadget 주소들(pc 자신은 포함하지 않음).

    따라간 gadget이 jmp/call gadget이거나 sd/adv를 모르면 그 gadget까지는 세고 거기서 멈춘다
    (주소가 gadget인 것은 확인됐지만 그 다음 목적지는 에뮬레이션 없이는 알 수 없으므로).
    max_len은 스택 값이 반복되는 경우의 안전 장치다.
    """
    out: list[int] = []
    cur = db.at(pc)
    cur_sp = sp  # cur gadget을 시작할 때의 rsp
    while len(out) < max_len:
        if cur is None or cur.kind != "ret" or cur.sd is None or cur.adv is None:
            break
        nxt = _read(sp, stk, cur_sp + cur.sd)  # cur의 ret이 꺼낼 주소
        if nxt is None:
            break
        g = db.at(nxt)
        if g is None:
            break
        out.append(nxt)
        cur, cur_sp = g, cur_sp + cur.adv  # ret까지 실행한 뒤의 rsp에서 다음 gadget 시작
    return out
