"""합성 트레이스 생성 — 동결 사례(정상·위반 17·경계 11/10)의 기준 트레이스와 13주차 추가 사례.

    uv run python -m ropecker.synth                 # traces/synth/*.jsonl.gz 4개를 다시 만든다(항상 같은 결과)
    uv run python -m ropecker.synth --extra         # cases/extra의 synth 스펙 → traces/extra/<check id>.jsonl.gz
    uv run python -m ropecker.synth --extra --only E7 [--force]

rop_vault(6주차 실습 바이너리)와 sysroot libc의 *실제* 명령 주소만 쓴다. 체인은 libc의 단순 gadget
(ret, pop r; ret)을 서로 다른 코드 페이지에서 골라 이어 붙여, 체인 안에서 윈도 밖 실행(체크포인트)이
생기게 한다. 정답(연쇄를 이룬 gadget 주소)은 헤더 'truth'에 넣는다.
보고서에는 "같은 바이너리 주소로 구성한 합성 트레이스"라고 밝힌다.
추가 사례의 스펙 문법(pick·nongadget·addr, pops, page, rsp_to, sys, ending)은 cases/extra/README.md에 있다.
"""

from __future__ import annotations

import argparse
import re
import sys
from bisect import bisect_left
from dataclasses import dataclass
from pathlib import Path

import capstone
from elftools.elf.elffile import ELFFile

from . import trace as trace_io
from .gadgetdb import GadgetDB, _ret_adv, _rsp_delta
from .image import Image, classify, exec_segments, module_entry
from .model import TRACE_FMT, TRACE_V, Gadget, Step, Trace, hx, parse_addr

ROOT = Path(__file__).resolve().parents[1]
ROP_VAULT = "target/bin/rop_vault"
LIBC = "target/sysroot/lib/x86_64-linux-gnu/libc.so.6"
LIBC_BASE = 0x7FFFF7D80000  # 합성용 libc 로드 주소(페이지 정렬)
FRAME = 0x7FFFFFFDE000  # 합성용 스택: vuln 복귀 주소 슬롯의 주소
PAGE = 4096
QWORD = 8
STACK_QWORDS = 32
FILL = 0x4141414141414141  # 버퍼를 넘친 'A'

GADGET_BYTES = {"ret": b"\xc3", "rdi": b"\x5f\xc3", "rsi": b"\x5e\xc3", "rax": b"\x58\xc3"}
POP_VALUE = {"rdi": 0x404060, "rsi": 0, "rax": 59}  # rdi = trusted_cmd("/bin/sh"), rax = execve
# glibc syscall 래퍼: syscall; cmp rax, -4096; ja … → 직접 분기가 있어 gadget이 아니다
SYSCALL_SITE = b"\x0f\x05\x48\x3d\x00\xf0\xff\xff\x77"
LIBC_MAIN_RET = b"\xff\xd0\x89\xc7\xe8"  # call rax(main); mov edi, eax; call exit

CASES = {
    # check id: (gadget 종류 목록, 끝 처리)
    "f2-violation": (["ret"] * 14 + ["rdi", "rsi", "rax"], "execve"),
    "f3-boundary-11": (["ret"] * 8 + ["rdi", "rsi", "rax"], "stop"),
    "f3-boundary-10": (["ret"] * 7 + ["rdi", "rsi", "rax"], "stop"),
}

# 13주차 추가 사례(스펙 → 트레이스)
WALK_LIMIT = 32  # 체인 항목 하나에서 간접 분기를 만날 때까지 따라갈 최대 명령 수
EXTRA_NOTE = "rop_vault·sysroot libc의 실제 주소로 구성한 합성 트레이스(13주차 추가 사례, cases/extra 스펙)"


@dataclass(frozen=True)
class Gad:
    addr: int
    reg: str | None  # None = 'ret', 아니면 'pop <reg>; ret'

    @property
    def slots(self) -> int:
        return 1 + (1 if self.reg else 0)


class _Machine:
    """rsp와 스택 메모리를 추적하며 스텝을 기록한다(페이지가 바뀐 스텝·syscall 스텝에 스냅샷)."""

    def __init__(self, mem: dict[int, int], rsp: int, qwords: int = STACK_QWORDS):
        self.mem, self.rsp = mem, rsp
        self.qwords = qwords
        self.steps: list[Step] = []
        self._page: int | None = None

    def emit(self, pc: int, sys: int | None = None) -> None:
        page = pc // PAGE
        if page != self._page or sys is not None:
            stk = tuple(self.mem.get(self.rsp + QWORD * i, 0) for i in range(self.qwords))
            self.steps.append(Step(pc=pc, sp=self.rsp, stk=stk, sys=sys))
        else:
            self.steps.append(Step(pc=pc))
        self._page = page

    def pop(self) -> int:
        value = self.mem.get(self.rsp, 0)
        self.rsp += QWORD
        return value


@dataclass(frozen=True)
class _Planned:
    """추가 사례 트레이스의 스텝 하나(명령을 실행하기 직전의 pc·rsp)."""

    pc: int
    rsp: int
    sys: int | None = None


def _symbols(path: Path) -> dict[str, int]:
    with open(path, "rb") as f:
        tab = ELFFile(f).get_section_by_name(".symtab")
        return {s.name: s["st_value"] for s in tab.iter_symbols() if s.name}


def _find_all(path: Path, pattern: bytes, base: int) -> list[int]:
    out = []
    for va, data in exec_segments(path):
        i = data.find(pattern)
        while i >= 0:
            out.append(base + va + i)
            i = data.find(pattern, i + 1)
    return out


def _walk(img: Image, start: int, until_text: str, limit: int = 64) -> list[int]:
    """start부터 선형으로 명령 주소를 모은다(until_text로 시작하는 명령까지 포함)."""
    out, pc = [], start
    for _ in range(limit):
        out.append(pc)
        ins = img.insn(pc)
        if ins.text.startswith(until_text):
            return out
        pc += ins.size
    raise ValueError(f"{hex(start)}부터 '{until_text}'를 찾지 못함")


def _num(value: int | str) -> int:
    return value if isinstance(value, int) else parse_addr(value)


class Builder:
    def __init__(self, root: Path = ROOT):
        self.root = root
        self.modules = [module_entry("rop_vault", ROP_VAULT, 0, root), module_entry("libc.so.6", LIBC, LIBC_BASE, root)]
        self.img = Image.from_header({"modules": self.modules}, root=root)
        sym = _symbols(root / ROP_VAULT)
        self.vuln_tail = [sym["main"] - 3, sym["main"] - 2, sym["main"] - 1]  # nop; leave; ret
        assert [self.img.insn(a).text for a in self.vuln_tail] == ["nop", "leave", "ret"], "vuln 끝이 예상과 다름"
        self.main_after_vuln = self._main_return_site(sym)
        sites = _find_all(root / LIBC, SYSCALL_SITE, LIBC_BASE)
        self.syscall_site = sites[0]
        self.libc_main_ret = next(iter(_find_all(root / LIBC, LIBC_MAIN_RET, LIBC_BASE)), None)
        # 추가 사례용(처음 쓸 때 만든다)
        self._gdb: GadgetDB | None = None
        self._sorted: list[Gadget] | None = None
        self._md: capstone.Cs | None = None
        self._sweeps: dict[str, list[int]] = {}

    def _main_return_site(self, sym: dict[str, int]) -> int:
        pc, vuln = sym["main"], sym["vuln"]
        for _ in range(128):
            ins = self.img.insn(pc)
            if ins.kind == "call" and ins.text.endswith(hex(vuln)):
                return pc + ins.size
            pc += ins.size
        raise ValueError("main에서 vuln 호출을 찾지 못함")

    def pick_chain(self, kinds: list[str]) -> list[Gad]:
        """종류별로 libc gadget을 고르되, 모든 gadget이 서로 다른 코드 페이지에 있게 한다."""
        used = {self.syscall_site // PAGE}
        chain = []
        for kind in kinds:
            for addr in _find_all(self.root / LIBC, GADGET_BYTES[kind], LIBC_BASE):
                last = addr + len(GADGET_BYTES[kind]) - 1
                if addr // PAGE in used or last // PAGE != addr // PAGE:
                    continue
                if kind == "ret":
                    ok = self.img.insn(addr).text == "ret"
                else:
                    ok = self.img.insn(addr).text == f"pop {kind}" and self.img.insn(addr + 1).text == "ret"
                if ok:
                    used.add(addr // PAGE)
                    chain.append(Gad(addr, None if kind == "ret" else kind))
                    break
            else:
                raise ValueError(f"서로 다른 페이지의 '{kind}' gadget이 부족함")
        return chain

    def header(self, check_id: str, truth: dict) -> dict:
        return {
            "fmt": TRACE_FMT,
            "v": TRACE_V,
            "collector": "synth",
            "case": check_id,
            "argv": ["rop_vault"],
            "stack_qwords": STACK_QWORDS,
            "modules": self.modules,
            "truth": truth,
            "note": "rop_vault(6주차 실습 바이너리)·sysroot libc의 실제 주소로 구성한 합성 트레이스",
        }

    def chain_trace(self, check_id: str, kinds: list[str], ending: str) -> Trace:
        chain = self.pick_chain(kinds)
        landing = self.syscall_site if ending == "execve" else self.syscall_site + 2  # cmp; ja … (gadget 아님)
        mem: dict[int, int] = {a: FILL for a in range(FRAME - 0x48, FRAME, QWORD)}  # buf 64 + saved rbp
        slot = FRAME
        for g in chain:
            mem[slot] = g.addr
            slot += QWORD
            if g.reg:
                mem[slot] = POP_VALUE[g.reg]
                slot += QWORD
        mem[slot] = landing
        if (slot - FRAME) // QWORD > STACK_QWORDS:
            raise ValueError("체인이 스냅샷(32 qword)보다 김")

        m = _Machine(mem, rsp=FRAME - 0x58)
        nop, leave, ret = self.vuln_tail
        m.emit(nop)
        m.emit(leave)
        m.rsp = FRAME  # leave: rsp = rbp(FRAME-8), pop rbp
        m.emit(ret)
        first_check = len(m.steps)
        expected = [g.addr for g in chain] + [landing]
        for i, g in enumerate(chain):
            assert m.pop() == expected[i]
            if g.reg:
                m.emit(g.addr)  # pop reg
                m.pop()
                m.emit(g.addr + 1)  # ret
            else:
                m.emit(g.addr)  # ret
        assert m.pop() == landing
        if ending == "execve":
            m.emit(landing, sys=59)
            end = {"end": "syscall", "sys": 59}
        else:
            m.emit(landing)
            end = {"end": "max_steps"}
        truth = {"chain": [hx(g.addr) for g in chain], "chain_len": len(chain), "first_checkpoint_step": first_check}
        return Trace(header=self.header(check_id, truth), steps=m.steps, end=end)

    def normal_trace(self) -> Trace:
        """정상 입력: vuln이 main으로 정상 복귀 → main이 libc로 복귀 → exit 호출."""
        r1 = self.main_after_vuln
        main_tail = _walk(self.img, r1, "ret")  # mov eax, 0; leave; ret
        mem = {FRAME - 0x48: int.from_bytes(b"hello\n\0\0", "little"), FRAME - QWORD: FRAME + 0x20, FRAME: r1}
        if self.libc_main_ret is not None:
            libc_site = self.libc_main_ret + 2  # mov edi, eax; call exit
            mem[FRAME + 0x28] = libc_site
        m = _Machine(mem, rsp=FRAME - 0x58)
        nop, leave, ret = self.vuln_tail
        m.emit(nop)
        m.emit(leave)
        m.rsp = FRAME
        m.emit(ret)
        assert m.pop() == r1
        for pc in main_tail:
            m.emit(pc)
            if self.img.insn(pc).text == "leave":
                m.rsp = FRAME + 0x28  # rsp = rbp(FRAME+0x20), pop rbp
        if self.libc_main_ret is not None:
            assert m.pop() == libc_site
            for pc in _walk(self.img, libc_site, "call"):
                m.emit(pc)
        truth = {"chain": [], "chain_len_max": 0, "first_checkpoint_step": 0}
        return Trace(header=self.header("f1-normal", truth), steps=m.steps, end={"end": "exit", "code": 0})

    def build_all(self) -> dict[str, Trace]:
        out = {"f1-normal": self.normal_trace()}
        for check_id, (kinds, ending) in CASES.items():
            out[check_id] = self.chain_trace(check_id, kinds, ending)
        return out

    # ------------------------------------------------------------------ 13주차 추가 사례(스펙 → 트레이스)
    def _db(self) -> GadgetDB:
        if self._gdb is None:
            self._gdb = GadgetDB.open(self.img, self.root / "data" / "gadgets")
        return self._gdb

    def _gadgets(self) -> list[Gadget]:
        if self._sorted is None:
            self._sorted = self._db().gadgets()
        return self._sorted

    def _decode(self, pc: int):
        """pc의 명령(capstone, detail 켜짐). 코드 밖이거나 디코드에 실패하면 ValueError."""
        if self._md is None:
            self._md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            self._md.detail = True
        code = self.img.read(pc, 15)
        ins = next(self._md.disasm(code, pc, 1), None) if code else None
        if ins is None:
            raise ValueError(f"{hex(pc)}: 코드 밖이거나 디코드할 수 없는 주소")
        return ins

    def _module(self, name: str):
        for mod in self.img.modules:
            if mod.name == name:
                return mod
        raise ValueError(f"모듈 {name!r}이 없습니다 (rop_vault 또는 libc.so.6)")

    def _addr(self, text: int | str) -> int:
        """'0x…'(런타임 주소) 또는 '모듈+0x…'(모듈 오프셋, 화면 출력의 표기)를 런타임 주소로."""
        if isinstance(text, str) and "+" in text:
            name, off = text.split("+", 1)
            return self._module(name).base + parse_addr(off)
        return _num(text)

    def _sweep(self, name: str) -> list[int]:
        """모듈 코드의 선형 디스어셈블 명령 경계(gadget DB의 aligned와 같은 방식, 실패하면 1바이트 건너뜀)."""
        if name not in self._sweeps:
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            out: list[int] = []
            for start, data in self._module(name).segments:
                off = 0
                while off < len(data):
                    end = off
                    for addr, size, _m, _o in md.disasm_lite(data[off:], start + off):
                        out.append(addr)
                        end = addr - start + size
                    off = end if end > off else off + 1
            self._sweeps[name] = out
        return self._sweeps[name]

    @staticmethod
    def _fits(start: int, end: int, mode: str, used: set[int], prev: int | None) -> bool:
        """page 조건: new = 아직 안 쓴 페이지, same = 바로 앞 항목과 같은 페이지, any = 상관없음."""
        page = start // PAGE
        if mode != "any" and end // PAGE != page:
            return False  # 조각이 페이지 하나 안에 있어야 진입이 체크포인트 하나로 정해진다
        if mode == "new":
            return page not in used
        if mode == "same":
            return page == prev
        return True

    def _in_module(self, addr: int, name: str) -> bool:
        return any(s <= addr < s + len(d) for s, d in self._module(name).segments)

    def _pick(self, flt: dict, mode: str, used: set[int], prev: int | None) -> Gadget:
        """gadget DB에서 조건에 맞는 gadget을 주소 순으로 찾아 index번째(기본 0)를 고른다."""
        module = flt.get("module", "libc.so.6")
        rx = re.compile(flt["asm"]) if "asm" in flt else None
        want, seen = flt.get("index", 0), 0
        for g in self._gadgets():
            if not self._in_module(g.addr, module):
                continue
            if "kind" in flt and g.kind != flt["kind"]:
                continue
            if "aligned" in flt and g.aligned != flt["aligned"]:
                continue
            if "n" in flt and g.n != flt["n"]:
                continue
            if not flt.get("n_min", 1) <= g.n <= flt.get("n_max", 1 << 30):
                continue
            if "sd_known" in flt and (g.sd is not None and g.adv is not None) != flt["sd_known"]:
                continue
            if rx and not rx.search(g.asm):
                continue
            if not self._fits(g.addr, g.end, mode, used, prev):
                continue
            if seen == want:
                return g
            seen += 1
        raise ValueError(f"조건에 맞는 gadget이 없습니다: {flt} (page={mode})")

    def _plain_before(self, module: str, addr: int) -> int | None:
        """addr 바로 앞 명령(선형 디스어셈블 기준)이 분기·syscall·push가 아니고 rsp 변화를 알면 그 주소."""
        bounds = self._sweep(module)
        i = bisect_left(bounds, addr)
        if i == 0 or i >= len(bounds) or bounds[i] != addr:
            return None
        start = bounds[i - 1]
        ins = self._decode(start)
        if start + ins.size != addr or classify(ins) != "other" or ins.mnemonic.startswith("push"):
            return None
        return start if _rsp_delta(ins) is not None else None

    def _nongadget(self, opts: dict, mode: str, used: set[int], prev: int | None) -> int:
        """gadget이 *아닌* 긴 조각(명령 n_min~n_max개, 끝은 ret)의 시작 주소.

        DB의 6개짜리 aligned ret gadget 앞으로 '평범한' 명령을 붙여 늘린다. 명령이 7개 이상이므로
        정의상 gadget이 아니다(논문 VII-B의 '긴 gadget', 연쇄를 끊는 데 쓴다).
        """
        module = opts.get("module", "libc.so.6")
        n_min, n_max = opts.get("n_min", 7), opts.get("n_max", 12)
        want, seen = opts.get("index", 0), 0
        db = self._db()
        for g in self._gadgets():
            if g.kind != "ret" or g.n != 6 or not g.aligned or g.sd is None or g.adv is None:
                continue
            if not self._in_module(g.addr, module):
                continue
            start, n = g.addr, g.n
            while n < n_max:
                before = self._plain_before(module, start)
                if before is None:
                    break
                start, n = before, n + 1
                if n >= n_min:
                    break
            if n < n_min or db.at(start) is not None or not self._fits(start, g.end, mode, used, prev):
                continue
            if seen == want:
                return start
            seen += 1
        raise ValueError(f"조건에 맞는 긴 조각(gadget 아님)이 없습니다: {opts} (page={mode})")

    def _execute(self, entry: dict, start: int, nxt: int, rsp: int, mem: dict[int, int],
                 plan: list[_Planned]) -> tuple[int, list[str]]:
        """체인 항목 하나를 간접 분기까지 따라가며 스텝과 스택 값을 채운다. (끝난 뒤 rsp, 명령 목록)

        - ret: 스택의 다음 슬롯에 nxt(다음 항목 주소)를 둔다. ret imm16이면 그만큼 더 건너뛴다.
        - jmp*/call*: 레지스터 값은 트레이스에 없으므로 '목적지 = nxt'로 둔다(call*은 복귀 주소를 쌓음).
        - 직접 jmp는 따라가고(gadget 접합), 조건 분기(jcc·loop 계열)는 '안 뜀'으로 본다.
        - pop은 pops 값을 차례로 쓰고(없으면 0), rsp를 정적으로 모르는 명령은 rsp_to로 옮긴다.
        """
        pops = list(entry.get("pops", []))
        rsp_to = entry.get("rsp_to")
        texts: list[str] = []
        pc = start
        for _ in range(WALK_LIMIT):
            ins = self._decode(pc)
            kind = classify(ins)
            text = f"{ins.mnemonic} {ins.op_str}".strip()
            texts.append(text)
            if kind == "syscall":
                if "sys" not in entry:
                    raise ValueError(f"{hex(pc)} syscall: 이 항목에 sys(시스템 콜 번호)를 적어 주세요")
                plan.append(_Planned(pc, rsp, entry["sys"]))
                pc += ins.size
                continue
            plan.append(_Planned(pc, rsp))
            if kind == "ret":
                adv = _ret_adv(ins)
                if adv is None:
                    raise ValueError(f"{hex(pc)} '{text}': retf 계열은 합성 스펙에서 지원하지 않습니다")
                mem[rsp] = nxt
                return rsp + adv, texts
            if kind in ("jmp_ind", "call_ind"):
                if kind == "call_ind":
                    rsp -= QWORD
                    mem[rsp] = pc + ins.size
                return rsp, texts
            if kind == "jmp":
                pc = ins.operands[0].imm
                continue
            if kind == "jcc":
                pc += ins.size
                continue
            if kind != "other":
                raise ValueError(f"{hex(pc)} '{text}': 체인 항목 안에 올 수 없는 명령({kind})")
            delta = _rsp_delta(ins)
            if delta is None:
                if rsp_to is None:
                    raise ValueError(f"{hex(pc)} '{text}': rsp를 정적으로 알 수 없어 이 항목에 rsp_to가 필요합니다")
                new = _num(rsp_to)
                if ins.mnemonic == "pop":
                    mem[rsp] = new  # pop rsp: 새 rsp 값을 스택에서 꺼낸다
                rsp, rsp_to = new, None
            else:
                if ins.mnemonic.startswith("pop"):
                    mem[rsp] = _num(pops.pop(0)) if pops else 0
                elif ins.mnemonic.startswith("push"):
                    mem[rsp - QWORD] = 0  # 레지스터 값은 트레이스에 없다
                rsp += delta
            pc += ins.size
        raise ValueError(f"{hex(start)}부터 명령 {WALK_LIMIT}개 안에 간접 분기가 없습니다")

    def spec_trace(self, check_id: str, spec: dict) -> Trace:
        """추가 사례의 합성 스펙(cases/extra/README.md) → 트레이스.

        동결 사례와 같이 vuln 끝(nop; leave; ret)에서 시작해 체인 항목을 차례로 실행한다.
        체인 스택은 실행 전에 모두 깔아 두고(공격 페이로드), 스냅샷은 그 스택을 읽는다.
        """
        ending = spec.get("ending", "execve")
        qwords = spec.get("stack_qwords", STACK_QWORDS)
        vuln_page = self.vuln_tail[0] // PAGE
        used, prev = {self.syscall_site // PAGE, vuln_page}, vuln_page
        starts: list[int] = []
        hows: list[str] = []
        for e in spec["chain"]:
            mode = e.get("page", "new")
            if "pick" in e:
                start, how = self._pick(e["pick"], mode, used, prev).addr, "pick"
            elif "nongadget" in e:
                start, how = self._nongadget(e["nongadget"], mode, used, prev), "nongadget"
            else:
                start, how = self._addr(e["addr"]), "addr"
            used.add(start // PAGE)
            prev = start // PAGE
            starts.append(start)
            hows.append(how)
        landing = self.syscall_site if ending == "execve" else self.syscall_site + 2  # cmp; ja … (gadget 아님)

        mem: dict[int, int] = {a: FILL for a in range(FRAME - 0x48, FRAME, QWORD)}  # buf 64 + saved rbp
        nop, leave, ret = self.vuln_tail
        plan = [_Planned(nop, FRAME - 0x58), _Planned(leave, FRAME - 0x58), _Planned(ret, FRAME)]
        mem[FRAME] = starts[0]
        rsp = FRAME + QWORD
        db = self._db()
        entries = []
        for i, (e, start) in enumerate(zip(spec["chain"], starts)):
            nxt = starts[i + 1] if i + 1 < len(starts) else landing
            rsp, texts = self._execute(e, start, nxt, rsp, mem, plan)
            entries.append({"addr": hx(start), "how": hows[i], "gadget": db.at(start) is not None, "asm": "; ".join(texts)})
        if ending == "execve":
            plan.append(_Planned(landing, rsp, 59))
            end = {"end": "syscall", "sys": 59}
        elif ending == "stop":
            plan.append(_Planned(landing, rsp))
            end = {"end": "max_steps"}
        else:  # none: 마지막 항목의 분기까지만 기록(착지 스텝 없음 → 체크포인트도 없음)
            end = {"end": "max_steps"}

        m = _Machine(mem, rsp=FRAME - 0x58, qwords=qwords)
        for st in plan:
            m.rsp = st.rsp
            m.emit(st.pc, sys=st.sys)
        header = {
            "fmt": TRACE_FMT,
            "v": TRACE_V,
            "collector": "synth",
            "case": check_id,
            "argv": ["rop_vault"],
            "stack_qwords": qwords,
            "modules": self.modules,
            "spec": spec,
            "entries": entries,
            "note": EXTRA_NOTE,
        }
        return Trace(header=header, steps=m.steps, end=end)


def _build_frozen() -> int:
    out_dir = ROOT / "traces" / "synth"
    for check_id, tr in Builder().build_all().items():
        problems = trace_io.validate(tr)
        if problems:
            raise SystemExit(f"{check_id}: {problems}")
        path = out_dir / f"{check_id}.jsonl.gz"
        trace_io.dump(tr, path)
        print(f"{path.relative_to(ROOT).as_posix()}: 스텝 {len(tr.steps)}, 정답 {tr.header['truth']}")
    return 0


def _build_extra(cases_path: str, only: set[str] | None, force: bool) -> int:
    from .extra import load_cases, trace_of

    try:
        cases = load_cases(cases_path, ROOT)
    except ValueError as e:
        print(f"사례 파일 오류: {e}", file=sys.stderr)
        return 2
    b = Builder()
    made = skipped = 0
    for case in cases:
        if only and case["id"] not in only:
            continue
        for chk in case["checks"]:
            if "synth" not in chk:
                continue
            path = ROOT / trace_of(chk)
            rel = path.relative_to(ROOT).as_posix()
            if path.exists() and not force:
                print(f"{rel}: 이미 있음(같은 입력을 유지하려고 덮어쓰지 않음, 다시 만들려면 --force)")
                skipped += 1
                continue
            try:
                tr = b.spec_trace(chk["id"], chk["synth"])
            except ValueError as e:
                print(f"{case['id']}/{chk['id']}: 만들 수 없음 — {e}", file=sys.stderr)
                return 2
            problems = trace_io.validate(tr)
            if problems:
                print(f"{case['id']}/{chk['id']}: 형식 문제 {problems}", file=sys.stderr)
                return 2
            trace_io.dump(tr, path)
            gadgets = sum(1 for e in tr.header["entries"] if e["gadget"])
            print(f"{rel}: 스텝 {len(tr.steps)}, 체인 항목 {len(tr.header['entries'])}개(그중 gadget {gadgets}개), 끝 {tr.end}")
            made += 1
    print(f"만듦 {made} · 건너뜀 {skipped}")
    return 0


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):  # Windows 콘솔에서도 한글이 깨지지 않게
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass
    ap = argparse.ArgumentParser(description="합성 트레이스를 만든다(기본: 동결 사례 4개).")
    ap.add_argument("--extra", action="store_true", help="13주차 추가 사례의 synth 스펙으로 traces/extra/를 만든다")
    ap.add_argument("--cases", default="cases/extra", help="--extra의 사례 파일·폴더 (기본 cases/extra)")
    ap.add_argument("--only", help="--extra에서 만들 사례 번호, 쉼표로 구분 (예: E7,E10)")
    ap.add_argument("--force", action="store_true", help="--extra에서 이미 있는 트레이스도 다시 만든다")
    args = ap.parse_args(argv)
    if not args.extra:
        return _build_frozen()
    only = {s.strip() for s in args.only.split(",") if s.strip()} if args.only else None
    return _build_extra(args.cases, only, args.force)


if __name__ == "__main__":
    raise SystemExit(main())
