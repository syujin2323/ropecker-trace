"""모듈 적재와 명령 해석.

트레이스 헤더의 modules(name, path, sha256, base)로 ELF 실행 세그먼트를 런타임 주소에 올리고,
런타임 주소 → (모듈, ELF 가상주소) 변환과 그 주소의 명령 분류(Insn)를 제공한다.
sha256이 헤더와 다르면 ValueError를 낸다(다른 libc로 분석하는 사고 방지).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

import capstone
from capstone import x86
from elftools.elf.elffile import ELFFile

from .model import Insn, parse_addr

_PF_X = 0x1
_MAX_INSN = 15  # x86 명령 최대 길이


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def exec_segments(elf_path: str | Path) -> list[tuple[int, bytes]]:
    """ELF의 실행 가능한 PT_LOAD 세그먼트를 (가상주소, 바이트) 목록으로."""
    with open(elf_path, "rb") as f:
        elf = ELFFile(f)
        return [
            (seg["p_vaddr"], seg.data())
            for seg in elf.iter_segments()
            if seg["p_type"] == "PT_LOAD" and seg["p_flags"] & _PF_X
        ]


def module_entry(name: str, path: str | Path, base: int, root: str | Path = ".") -> dict:
    """트레이스 헤더 modules 항목. path는 root 기준 상대 경로로 적는다."""
    rel = Path(path)
    return {"name": name, "path": rel.as_posix(), "sha256": sha256_file(Path(root) / rel), "base": hex(base)}


def classify(ins) -> str:
    """capstone 명령(detail 켜짐)을 model.InsnKind로 분류."""
    iid = ins.id
    if iid in (x86.X86_INS_RET, x86.X86_INS_RETF, x86.X86_INS_RETFQ):
        return "ret"
    if iid == x86.X86_INS_SYSCALL:
        return "syscall"
    if iid in (x86.X86_INS_JMP, x86.X86_INS_LJMP):
        direct = len(ins.operands) == 1 and ins.operands[0].type == x86.X86_OP_IMM
        return "jmp" if direct else "jmp_ind"
    if iid in (x86.X86_INS_CALL, x86.X86_INS_LCALL):
        direct = len(ins.operands) == 1 and ins.operands[0].type == x86.X86_OP_IMM
        return "call" if direct else "call_ind"
    # jcc, jrcxz는 JUMP군, loop·loope·loopne은 JUMP군이 아니라 BRANCH_RELATIVE군만 가진다
    if capstone.CS_GRP_JUMP in ins.groups or capstone.CS_GRP_BRANCH_RELATIVE in ins.groups:
        return "jcc"
    return "other"


@dataclass
class _Module:
    name: str
    base: int
    segments: list[tuple[int, bytes]]  # (런타임 시작 주소, 바이트)
    sha256: str = ""  # gadget DB가 같은 파일로 만든 것인지 확인할 때 쓴다


class Image:
    """런타임 주소 공간의 코드 이미지."""

    def __init__(self, modules: list[_Module]):
        self.modules = modules
        self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        self._md.detail = True
        self._cache: dict[int, Insn] = {}

    @classmethod
    def from_header(cls, header: dict, root: str | Path = ".") -> "Image":
        root = Path(root)
        mods: list[_Module] = []
        for m in header.get("modules", []):
            path = root / m["path"]
            if not path.is_file():
                raise ValueError(f"모듈 파일이 없습니다: {m['path']} (기준 폴더 {root.as_posix()})")
            if sha256_file(path) != m["sha256"]:
                raise ValueError(f"{m['name']}: 파일 sha256이 트레이스 헤더와 다릅니다(다른 빌드의 파일)")
            base = parse_addr(m["base"])
            mods.append(_Module(m["name"], base, [(base + va, data) for va, data in exec_segments(path)], m["sha256"]))
        return cls(mods)

    def _find(self, addr: int) -> tuple[_Module, int, bytes] | None:
        for mod in self.modules:
            for start, data in mod.segments:
                if start <= addr < start + len(data):
                    return mod, start, data
        return None

    def locate(self, addr: int) -> tuple[str, int] | None:
        """런타임 주소 → (모듈 이름, ELF 가상주소). 코드 밖이면 None."""
        hit = self._find(addr)
        return (hit[0].name, addr - hit[0].base) if hit else None

    def read(self, addr: int, size: int) -> bytes:
        """코드 바이트 읽기(세그먼트 경계에서 잘림). 코드 밖이면 b''."""
        hit = self._find(addr)
        if not hit:
            return b""
        _, start, data = hit
        return data[addr - start : addr - start + size]

    def insn(self, addr: int) -> Insn:
        """addr에서 디코드한 명령. 코드 밖이거나 디코드에 실패하면 kind='bad'."""
        cached = self._cache.get(addr)
        if cached is not None:
            return cached
        code = self.read(addr, _MAX_INSN)
        decoded = next(self._md.disasm(code, addr, 1), None) if code else None
        if decoded is None:
            result = Insn(1, "bad", "(코드 밖)" if not code else "(디코드 실패)")
        else:
            text = f"{decoded.mnemonic} {decoded.op_str}".strip()
            result = Insn(decoded.size, classify(decoded), text)
        self._cache[addr] = result
        return result
