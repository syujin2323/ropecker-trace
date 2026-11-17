"""gdb(파이썬 API)로 qemu-user gdbstub에 붙어 한 명령씩 실행하며 트레이스 v1을 기록한다.

collect/run.sh가 컨테이너 안에서 실행한다(gdb 내장 파이썬, 표준 라이브러리만 사용).
환경 변수: RC_OUT(출력 경로), RC_MAX(최대 스텝), RC_PORT(gdbstub 포트), RC_ARGV(대상 인자)
형식은 docs/design.md "트레이스 v1": 모든 스텝에 pc, 실행 페이지가 바뀐 스텝과 syscall 스텝에 sp·stk.
"""

import gzip
import hashlib
import io
import json
import os
import struct

import gdb  # noqa: F401  (gdb 안에서만 import 가능)

BIN = "target/bin/rop_vault"
SYSROOT = "target/sysroot"
LIBS = {
    "libc.so.6": f"{SYSROOT}/lib/x86_64-linux-gnu/libc.so.6",
    "ld-linux-x86-64.so.2": f"{SYSROOT}/lib64/ld-linux-x86-64.so.2",
}
PAGE = 4096
STACK_QWORDS = 32
MASK = (1 << 64) - 1

OUT = os.environ["RC_OUT"]
MAX_STEPS = int(os.environ.get("RC_MAX", "200000"))
PORT = os.environ.get("RC_PORT", "1234")
ARGV = os.environ.get("RC_ARGV", "rop_vault main").split()


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        h.update(f.read())
    return h.hexdigest()


def dynamic_vaddr(path):
    """ELF64 실행 파일의 PT_DYNAMIC 가상주소(no-PIE라 런타임 주소와 같다)."""
    with open(path, "rb") as f:
        data = f.read()
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        off = phoff + i * phentsize
        if struct.unpack_from("<I", data, off)[0] == 2:  # PT_DYNAMIC
            return struct.unpack_from("<Q", data, off + 0x10)[0]
    raise RuntimeError(f"{path}: PT_DYNAMIC 없음")


def read_cstring(addr, limit=256):
    raw = bytes(gdb.selected_inferior().read_memory(addr, limit))
    return raw.split(b"\0", 1)[0].decode("utf-8", "replace")


def reg(name):
    return int(gdb.parse_and_eval(f"${name}")) & MASK


def read_stack(sp):
    inf = gdb.selected_inferior()
    for n in range(STACK_QWORDS, 0, -1):  # 스택 끝 근처면 읽을 수 있는 만큼만
        try:
            raw = bytes(inf.read_memory(sp, 8 * n))
            vals = list(struct.unpack(f"<{n}Q", raw))
            return vals + [0] * (STACK_QWORDS - n)
        except gdb.MemoryError:
            continue
    return [0] * STACK_QWORDS


def module_bases():
    """동적 링커의 link_map에서 라이브러리 로드 주소(l_addr)를 직접 읽는다.

    qemu-user 대상에서는 gdb의 공유 라이브러리 추적이 동작하지 않을 수 있어서,
    rop_vault의 DT_DEBUG → r_debug.r_map → link_map 목록을 메모리에서 따라간다.
    """
    inf = gdb.selected_inferior()
    addr, r_debug = dynamic_vaddr(BIN), 0
    while True:
        tag, val = struct.unpack("<qQ", bytes(inf.read_memory(addr, 16)))
        if tag == 0:
            break
        if tag == 21:  # DT_DEBUG
            r_debug = val
            break
        addr += 16
    if not r_debug:
        raise RuntimeError("DT_DEBUG(r_debug)를 찾지 못함 — main 이전에 호출됐는지 확인")
    bases = {}
    lm = struct.unpack("<Q", bytes(inf.read_memory(r_debug + 8, 8)))[0]  # r_debug.r_map
    while lm:
        l_addr, l_name, _l_ld, l_next = struct.unpack("<QQQQ", bytes(inf.read_memory(lm, 32)))
        name = os.path.basename(read_cstring(l_name)) if l_name else ""
        if name in LIBS:
            bases[name] = l_addr
        lm = l_next
    missing = set(LIBS) - set(bases)
    if missing:
        raise RuntimeError(f"link_map에서 찾지 못한 라이브러리: {sorted(missing)}")
    return bases


def main():
    gdb.execute("set pagination off")
    gdb.execute("set confirm off")
    gdb.execute("set architecture i386:x86-64")
    gdb.execute(f"file {BIN}")
    gdb.execute(f"set sysroot {SYSROOT}")
    gdb.execute(f"target remote localhost:{PORT}")
    gdb.execute("break *main")  # main의 첫 명령부터 기록
    gdb.execute("continue")
    gdb.execute("delete")
    # 매 스텝 멈춤 위치 메시지를 화면에 찍지 않는다(속도). 결과 요약은 끝에서 다시 켜고 출력한다.
    gdb.execute("set suppress-cli-notifications on")
    gdb.execute("set logging file /dev/null")
    gdb.execute("set logging redirect on")
    gdb.execute("set logging enabled on")

    bases = module_bases()
    modules = [{"name": "rop_vault", "path": BIN, "sha256": sha256(BIN), "base": "0x0"}]
    for name, path in LIBS.items():
        modules.append({"name": name, "path": path, "sha256": sha256(path), "base": hex(bases[name])})
    header = {
        "fmt": "ropecker-trace",
        "v": 1,
        "collector": "gdb-qemu",
        "argv": ARGV,
        "start": "main",
        "stack_qwords": STACK_QWORDS,
        "modules": modules,
    }

    raw = gzip.GzipFile(filename="", mode="wb", fileobj=open(OUT, "wb"), mtime=0)
    out = io.TextIOWrapper(raw, encoding="utf-8", newline="\n")
    out.write(json.dumps(header, ensure_ascii=False) + "\n")
    end = {"end": "max_steps"}
    prev_page = None
    steps = 0
    inf = gdb.selected_inferior()
    # 종료·시그널은 화면 메시지가 아니라 gdb 이벤트로 받는다(출력 리다이렉트와 무관하게 동작)
    seen = {"exit": None, "signal": None}

    def on_exit(ev):
        seen["exit"] = getattr(ev, "exit_code", 0)

    def on_stop(ev):
        if isinstance(ev, gdb.SignalEvent):
            seen["signal"] = ev.stop_signal

    gdb.events.exited.connect(on_exit)
    gdb.events.stop.connect(on_stop)
    for _ in range(MAX_STEPS):
        steps += 1
        pc = reg("pc")
        rec = {"pc": hex(pc)}
        is_syscall = bytes(inf.read_memory(pc, 2)) == b"\x0f\x05"
        if pc // PAGE != prev_page or is_syscall:
            sp = reg("rsp")
            rec["sp"] = hex(sp)
            rec["stk"] = [hex(v) for v in read_stack(sp)]
            if is_syscall:
                rec["sys"] = reg("rax")
        out.write(json.dumps(rec) + "\n")
        prev_page = pc // PAGE
        try:
            gdb.execute("stepi", to_string=True)
        except gdb.error:
            pass  # 프로그램이 끝난 뒤의 stepi 오류는 아래에서 종료로 처리
        if seen["exit"] is not None or not inf.threads():
            end = {"end": "exit", "code": int(seen["exit"] or 0)}
            break
        if seen["signal"]:
            end = {"end": "signal", "signal": seen["signal"]}
            break
    out.write(json.dumps(end) + "\n")
    out.close()
    raw.fileobj.close()
    gdb.execute("set logging enabled off")
    print(f"[gdb_trace] {OUT}: 스텝 {steps}, {end}")


main()
