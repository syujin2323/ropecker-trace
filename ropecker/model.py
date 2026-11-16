"""레인 사이의 계약: 공유 데이터 타입과 형식 상수.

여기를 바꾸면 반드시 docs/design.md도 함께 고친다(형식의 단일 출처는 design.md).
모든 주소는 int로 다루고, 파일에 쓸 때만 "0x..." 16진 문자열로 바꾼다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------- 파일 형식
TRACE_FMT = "ropecker-trace"
TRACE_V = 1
GADGETDB_FMT = "ropecker-gadgetdb"
GADGETDB_V = 1
RESULT_FMT = "ropecker-result"
RESULT_V = 1

# ---------------------------------------------------------------- 명령 분류
InsnKind = Literal["ret", "jmp_ind", "call_ind", "jmp", "jcc", "call", "syscall", "other", "bad"]
INDIRECT_KINDS: frozenset[str] = frozenset({"ret", "jmp_ind", "call_ind"})  # gadget을 끝낼 수 있는 분기
DIRECT_BRANCH_KINDS: frozenset[str] = frozenset({"jmp", "jcc", "call"})  # gadget 안에 있으면 안 되는 분기

# ---------------------------------------------------------------- 판정 값 (화면·JSON 값은 한글, 키는 ASCII)
VERDICT_NORMAL = "정상"
VERDICT_ROP = "ROP"
VERDICT_UNCHECKED = "미검사"  # --no-check(보호 적용 전) 실행

EXIT_NORMAL = 0
EXIT_ROP = 1
EXIT_ERROR = 2  # 형식 오류·미구현 등

# x86-64 위험 시스템 콜(논문 V-B: DEP를 끄거나 새 프로세스를 띄울 수 있는 호출)
RISKY_SYSCALLS: frozenset[int] = frozenset({9, 10, 25, 59})  # mmap, mprotect, mremap, execve


# ---------------------------------------------------------------- 트레이스
@dataclass(frozen=True)
class Step:
    """명령 하나를 실행하기 *직전*의 상태.

    pc는 모든 스텝에 있다. sp·stk(스택 위쪽 qword 목록)는 실행 페이지가 바뀐 스텝과
    syscall 스텝에만 있다(체크포인트가 될 수 있는 스텝). sys는 syscall 스텝의 rax.
    """

    pc: int
    sp: int | None = None
    stk: tuple[int, ...] | None = None
    sys: int | None = None


@dataclass
class Trace:
    header: dict
    steps: list[Step]
    end: dict = field(default_factory=lambda: {"end": "max_steps"})


# ---------------------------------------------------------------- 명령·분기·gadget
@dataclass(frozen=True)
class Insn:
    size: int
    kind: str  # InsnKind
    text: str  # 예: "pop rdi"


@dataclass(frozen=True)
class Branch:
    """LBR 항목 하나에 해당하는 간접 분기(ret/jmp*/call*)."""

    step: int  # 분기 명령이 실행된 스텝 번호(트레이스 행 순서)
    src: int
    dst: int
    kind: str


@dataclass(frozen=True)
class Gadget:
    """addr에서 시작해 간접 분기로 끝나는, 직접 분기 없는 명령 6개 이하 조각.

    sd: gadget 시작 시점 rsp부터 ret 슬롯까지 바이트 거리(ret gadget만, 알 수 없으면 None)
    adv: gadget 실행 뒤 rsp 변화량(알 수 없으면 None)
    aligned: 시작 주소가 선형 디스어셈블의 명령 경계와 일치하는지
    """

    addr: int
    n: int
    end: int
    kind: str
    sd: int | None
    adv: int | None
    aligned: bool
    asm: str


# ---------------------------------------------------------------- 실행 파라미터
@dataclass(frozen=True)
class Params:
    window: int = 8192  # W 바이트(페이지 W/4096개)
    threshold: int = 11  # T
    cmp: Literal["ge", "gt"] = "ge"  # 11주차 보고서 기준 "≥ T", 논문은 "> T"(--cmp gt)
    lbr_depth: int = 16
    align_check: bool = False
    check: bool = True  # False면 --no-check(보호 적용 전)
    risky_syscalls: frozenset[int] = RISKY_SYSCALLS

    def is_rop(self, chain_len: int) -> bool:
        if self.cmp == "gt":
            return chain_len > self.threshold
        return chain_len >= self.threshold

    def as_json(self) -> dict:
        return {
            "window": self.window,
            "threshold": self.threshold,
            "cmp": self.cmp,
            "lbr_depth": self.lbr_depth,
            "align_check": self.align_check,
            "check": self.check,
            "risky_syscalls": sorted(self.risky_syscalls),
        }


def hx(value: int) -> str:
    """주소를 파일용 16진 문자열로."""
    return hex(value)


def parse_addr(value: str | int) -> int:
    """'0x..' 문자열 또는 정수를 주소(int)로."""
    if isinstance(value, int):
        return value
    return int(value, 16) if value.lower().startswith("0x") else int(value)
