"""합성 트레이스 생성 (리더 레인, M0 2일차에 구현).

동결 사례(정상·위반 17·경계 11/10)의 기준 트레이스를 만든다. rop_vault·libc의 실제 gadget
주소로 체인을 구성하고, 체크포인트가 체인 중간에 생기도록 서로 다른 코드 페이지의 gadget을 섞는다.
정답(연쇄를 이룬 gadget 주소)은 헤더 'truth'에 넣는다. 보고서에는 '같은 바이너리 주소로 구성한
트레이스'라고 밝힌다.
"""

from __future__ import annotations

from .model import Trace


def make_chain(img, gadgets: list[int], launch_ret: int, stack_qwords: int = 32) -> Trace:
    raise NotImplementedError("synth.make_chain: 리더 레인(M0 2일차)")
