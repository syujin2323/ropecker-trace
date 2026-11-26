"""E3: gadget DB의 rsp 변화(sd·adv) 계산 오류 — 이름·접두사로 판단하던 부분.

수정 전: popcnt를 pop으로, 16비트 push/pop을 8바이트로, enter를 0으로, iretq를 0으로 셈.
모르면 None(논문 Table II 'need emulation')이어야 하고, 알면 실제 값이어야 한다.
"""

import pytest

from ropecker.gadgetdb import scan


def first(hexcode):
    g = {g.addr: g for g in scan(bytes.fromhex(hexcode), 0x1000)}[0x1000]
    return g.sd, g.adv


def test_popcnt_is_not_pop():
    assert first("f3480fb8c3" "c3") == (0, 8)  # popcnt rax, rbx; ret — rsp는 안 변함


@pytest.mark.parametrize(
    "hexcode, sd",
    [("6650c3", -2), ("6658c3", 2), ("669cc3", -2), ("669dc3", 2), ("66680100c3", -2), ("660fa0c3", -2)],
)  # push ax / pop ax / pushfw / popfw / push imm16 / push fs (66 접두사 = 16비트)
def test_16bit_push_pop_is_2_bytes(hexcode, sd):
    assert first(hexcode) == (sd, sd + 8)


def test_64bit_push_pop_unchanged():
    assert first("50c3") == (-8, 0) and first("58c3") == (8, 16) and first("9cc3") == (-8, 0)
    assert first("0fa0c3") == (-8, 0)  # push fs는 64비트 모드에서 8바이트


def test_enter_level0_moves_rsp_by_8_plus_size():
    assert first("c8080000c3") == (-16, -8)  # enter 8, 0: push rbp; sub rsp, 8
    assert first("c8000000c3") == (-8, 0)  # enter 0, 0
    assert first("c8ffff00c3") == (-(8 + 0xFFFF), -(8 + 0xFFFF) + 8)  # imm16은 부호 없는 값


def test_enter_nested_is_unknown():
    assert first("c8080001c3") == (None, None)  # enter 8, 1: 중첩 수준 > 0 → 정적으로 모름


def test_sixteen_bit_pop_sp_is_pivot():
    assert first("665cc3") == (None, None)  # pop sp: 스택 피벗


@pytest.mark.parametrize("hexcode", ["48cfc3", "480f07c3"])  # iretq / sysretq
def test_iret_sysret_are_unknown(hexcode):
    assert first(hexcode) == (None, None)


def test_16bit_ret_is_unknown():
    g = {g.addr: g for g in scan(bytes.fromhex("66c3"), 0x1000)}[0x1000]
    assert g.adv is None  # 16비트 ret은 몇 바이트를 꺼내는지 CPU마다 다름
