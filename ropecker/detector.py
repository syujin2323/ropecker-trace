"""통합 판정 (레인: past·infra).

체크포인트마다 과거 연쇄(lbr → past)와 미래 연쇄(future)를 구해 합산하고,
Params.is_rop(합)이면 그 지점에서 ROP로 판정하고 멈춘다(논문: 프로세스 종료).
탐지가 없으면 '가장 긴 연쇄가 나온 체크포인트'의 값을 결과에 남긴다.
결과 형식은 docs/design.md "결과 v1"(cli._print_summary가 이 키들을 읽는다).
"""

from __future__ import annotations

from .model import Params, Trace


def detect(tr: Trace, img, db, p: Params) -> dict:
    raise NotImplementedError("detector.detect: 통합 레인(W12)")
