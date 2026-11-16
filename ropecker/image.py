"""모듈 적재와 명령 해석 (리더 레인, M0 2일차에 구현).

트레이스 헤더의 modules(name, path, sha256, base)로 ELF 실행 세그먼트를 메모리 주소에 올리고,
런타임 주소 → (모듈, 오프셋) 변환과 그 주소의 명령 분류(Insn)를 제공한다.
sha256이 헤더와 다르면 ValueError(다른 libc로 분석하는 사고 방지, 계획의 리스크 1).
"""

from __future__ import annotations

from pathlib import Path

from .model import Insn


def exec_segments(elf_path: str | Path) -> list[tuple[int, bytes]]:
    """ELF의 실행 가능 세그먼트를 (가상주소, 바이트) 목록으로."""
    raise NotImplementedError("image.exec_segments: 리더 레인(M0 2일차)")


class Image:
    """런타임 주소 공간의 코드 이미지."""

    @classmethod
    def from_header(cls, header: dict, root: str | Path = ".") -> "Image":
        raise NotImplementedError("image.Image.from_header: 리더 레인(M0 2일차)")

    def locate(self, addr: int) -> tuple[str, int] | None:
        """런타임 주소 → (모듈 이름, ELF 가상주소). 코드 밖이면 None."""
        raise NotImplementedError("image.Image.locate")

    def insn(self, addr: int) -> Insn:
        """addr에서 디코드한 명령. kind는 model.InsnKind 중 하나, 디코드 실패는 'bad'."""
        raise NotImplementedError("image.Image.insn")
