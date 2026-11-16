"""gadget DB (레인: db).

논문 VI-A의 IG 데이터베이스에 해당한다. 코드 섹션의 *모든 바이트 오프셋*에서 시작해
직접 분기 없이 간접 분기(ret/jmp*/call*)로 끝나는 명령 6개 이하 조각을 gadget으로 기록한다.
형식은 docs/design.md "gadget DB v1".
"""

from __future__ import annotations

from pathlib import Path

from .model import Gadget


def scan(code: bytes, base: int, max_insns: int = 6) -> list[Gadget]:
    """코드 바이트(가상주소 base에서 시작)의 모든 오프셋에서 gadget을 찾는다.

    - n: gadget의 명령 개수(끝의 간접 분기 포함), end: 끝 분기 명령의 주소
    - 조각 안에 직접 분기(jmp/jcc/call)가 있거나 디코드에 실패하면 gadget이 아니다.
    - aligned: base부터 선형 디스어셈블했을 때 그 주소가 명령 경계인지
    - sd/adv: ret gadget에서 push/pop/add rsp,imm 등으로 계산 가능한 경우만, 그 밖은 None
    """
    raise NotImplementedError("gadgetdb.scan: db 레인(W12)")


def build(elf_path: str | Path, max_insns: int = 6) -> list[Gadget]:
    """ELF 하나의 gadget 목록(주소는 ELF 가상주소 기준). 실행 세그먼트마다 scan을 부른다."""
    raise NotImplementedError("gadgetdb.build: db 레인(W12)")


def save(gadgets: list[Gadget], path: str | Path, module: str, sha256: str) -> None:
    """gadget DB v1(jsonl.gz)로 저장."""
    raise NotImplementedError("gadgetdb.save: db 레인(W12)")


class GadgetDB:
    """런타임 주소로 gadget을 찾는 조회기. 모듈별 DB를 Image의 base로 재배치해서 쓴다."""

    @classmethod
    def open(cls, img, db_dir: str | Path) -> "GadgetDB":
        raise NotImplementedError("gadgetdb.GadgetDB.open: db 레인(W12)")

    def at(self, addr: int) -> Gadget | None:
        """addr(런타임 주소)에서 시작하는 gadget, 없으면 None. 반환 Gadget.addr도 런타임 주소."""
        raise NotImplementedError("gadgetdb.GadgetDB.at")


def compare_ropgadget(gadgets: list[Gadget], rg_output: str) -> dict:
    """ROPgadget 출력과 교차검증: {'only_ours': [...], 'only_rg': [...], 'both': n}."""
    raise NotImplementedError("gadgetdb.compare_ropgadget: db 레인(W13)")
