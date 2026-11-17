"""image.py: 실제 대상 바이너리(target/bin/rop_vault)와 sysroot libc로 확인한다."""

from pathlib import Path

import pytest

from ropecker.image import Image, exec_segments, module_entry

ROOT = Path(__file__).resolve().parents[1]
ROP_VAULT = "target/bin/rop_vault"
LIBC = "target/sysroot/lib/x86_64-linux-gnu/libc.so.6"
LIBC_BASE = 0x7FFFF7D80000


@pytest.fixture(scope="module")
def img():
    header = {
        "modules": [
            module_entry("rop_vault", ROP_VAULT, 0, ROOT),
            module_entry("libc.so.6", LIBC, LIBC_BASE, ROOT),
        ]
    }
    return Image.from_header(header, root=ROOT)


def test_exec_segments_contains_text():
    segs = exec_segments(ROOT / ROP_VAULT)
    assert any(start <= 0x4011DE < start + len(data) for start, data in segs)


def test_week6_gadget_addresses_match_course_binary(img):
    """6주차 풀이 스크립트의 POP_RDI(0x4011de)·RET(0x4011df)와 같은 위치여야 한다."""
    assert img.insn(0x4011DE).text == "pop rdi"
    assert img.insn(0x4011DE).kind == "other"
    assert img.insn(0x4011DF).kind == "ret"
    assert img.locate(0x4011DE) == ("rop_vault", 0x4011DE)


def test_classify_direct_and_indirect_branches(img):
    plt_puts = 0x401090  # puts@plt.sec: endbr64; bnd jmp [rip+...]
    first = img.insn(plt_puts)
    assert first.text.startswith("endbr64")
    assert img.insn(plt_puts + first.size).kind == "jmp_ind"


def test_libc_syscall_and_runtime_base(img):
    seg_start, data = next((s, d) for s, d in exec_segments(ROOT / LIBC))
    off = data.find(b"\x0f\x05")  # syscall
    addr = LIBC_BASE + seg_start + off
    assert img.insn(addr).kind == "syscall"
    assert img.locate(addr) == ("libc.so.6", seg_start + off)


def test_outside_code_is_bad(img):
    assert img.locate(0x10) is None
    assert img.insn(0x10).kind == "bad"


def test_sha256_mismatch_is_rejected():
    entry = module_entry("rop_vault", ROP_VAULT, 0, ROOT)
    entry["sha256"] = "0" * 64
    with pytest.raises(ValueError):
        Image.from_header({"modules": [entry]}, root=ROOT)
