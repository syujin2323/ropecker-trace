"""13주차 추가 검증 사례: 사례 파일 형식 검사, 합성 스펙 → 트레이스, 실행기(run_cases --cases).

팀원이 cases/extra에 사례 파일을 올리면 이 테스트가 형식을 먼저 확인한다(CI 3 OS).
사례의 '결과'가 기대와 다른 것은 실패가 아니라 반례이므로 여기서는 결과를 검사하지 않는다.
"""

import json
from pathlib import Path

import capstone
import pytest

from ropecker import synth
from ropecker import trace as trace_io
from ropecker.detector import detect
from ropecker.extra import EXTRA_DIR, load_cases, synth_problems, trace_header, trace_of, validate_case
from ropecker.gadgetdb import GadgetDB
from ropecker.image import Image
from ropecker.model import Params
from ropecker.synth import FRAME, Builder, _stack_effect
from scripts import run_cases

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = EXTRA_DIR / "examples"
RET = {"pick": {"asm": "^ret$"}}


def _case(**over):
    case = {
        "id": "E99",
        "제목": "시험",
        "담당": "송유진",
        "방향": "경계값",
        "구분": "경계",
        "입력": "ret 체인",
        "기대 결과": "ROP",
        "checks": [{"id": "t-ret", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP"}}],
    }
    case.update(over)
    return case


@pytest.fixture(scope="module")
def builder():
    return Builder(ROOT)


def _detect(tr, **params):
    img = Image.from_header(tr.header, root=ROOT)
    db = GadgetDB.open(img, ROOT / "data" / "gadgets")
    return detect(tr, img, db, Params(**params))


# ---------------------------------------------------------------- 사례 파일 형식
@pytest.mark.parametrize("folder", [EXTRA_DIR, EXAMPLES])
def test_committed_case_files_are_valid(folder):
    """cases/extra(팀원 사례)와 examples(형식 예시)의 모든 파일이 형식 검사를 통과한다."""
    cases = load_cases(folder, ROOT)
    assert [c["id"] for c in cases] == sorted((c["id"] for c in cases), key=lambda s: int(s[1:]))


def test_valid_case_has_no_problems():
    assert validate_case(_case()) == []


@pytest.mark.parametrize(
    "over, needle",
    [
        ({"id": "7"}, "id는 E와 숫자"),
        ({"방향": "기타"}, "방향은"),
        ({"구분": "공격"}, "구분은"),
        ({"checks": []}, "checks가 비어"),
        ({"checks": [{"id": "Bad_ID", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP"}}]}, "check id"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP", "len": 3}}]}, "모르는 기대값 키"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "expect": {"verdict": "탐지"}}]}, "expect.verdict"),
        ({"checks": [{"id": "t", "expect": {"verdict": "ROP"}}]}, "정확히 하나"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "trace": "traces/x.jsonl.gz", "expect": {"verdict": "ROP"}}]},
         "정확히 하나"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP", "detect_step_max": "3"}}]},
         "detect_step_max는 0 이상의 정수"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP", "chain_len_min": -1}}]},
         "chain_len_min는 0 이상의 정수"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP", "gadgets_nonempty": "yes"}}]},
         "gadgets_nonempty는"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP", "trace_end": 0}}]}, "trace_end는"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "parmas": {}, "expect": {"verdict": "ROP"}}]}, "check에 모르는 키"),
        ({"작성자": "송유진"}, "모르는 키"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "args": ["--threshold=12"], "expect": {"verdict": "ROP"}}]},
         "args에"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "args": ["--thr", "12"], "expect": {"verdict": "ROP"}}]}, "args에"),
        ({"params": {"window": True}}, "window는 양의 정수"),
        ({"결과 분석": {"분류": "구현 버그", "원인": "x"}}, "'결과 분석'에 모르는 키"),
        ({"checks": [{"id": "t", "trace": "/tmp/x.gz", "expect": {"verdict": "ROP"}}]}, "저장소 루트 기준"),
        ({"checks": [{"id": "t", "synth": {"chain": [RET]}, "args": ["--cmp", "gt"], "expect": {"verdict": "ROP"}}]},
         "args에"),
        ({"checks": [{"id": "t", "pytest": "tests/test_cli.py", "expect": {"pass": True}}]}, "cases/extra/ 아래"),
        ({"checks": [{"id": "t", "pytest": "cases/extra/u/t.py", "expect": {"verdict": "ROP"}}]}, "pass"),
        ({"params": {"threshold": 0}}, "threshold는 양의 정수"),
        ({"결과 분석": {"분류": "버그"}}, "분류는"),
    ],
)
def test_validate_case_reports_mistakes(over, needle):
    problems = validate_case(_case(**over))
    assert any(needle in p for p in problems), problems


@pytest.mark.parametrize(
    "spec, needle",
    [
        ({"chain": []}, "비어 있습니다"),
        ({"chain": [RET], "ending": "exit"}, "synth.ending"),
        ({"chain": [RET], "stack_qwords": 0}, "stack_qwords"),
        ({"chain": [RET], "extra": 1}, "모르는 키"),
        ({"chain": [{"pick": {"asm": "^ret$"}, "addr": "0x1"}]}, "정확히 하나"),
        ({"chain": [{"pick": {"opcode": "c3"}}]}, "pick에 모르는 키"),
        ({"chain": [{"pick": {"asm": "("}}]}, "정규식"),
        ({"chain": [{"pick": {"module": "ld.so"}}]}, "module은"),
        ({"chain": [{"addr": "libc+0x10"}]}, "addr는"),
        ({"chain": [{"addr": "0x401000", "page": "new"}]}, "page는 pick·nongadget에만"),
        ({"chain": [{"nongadget": {"n_min": -1}}]}, "0 이상의 정수"),
        ({"chain": [{"pick": {"asm": "^ret$"}, "pops": ["rdi"]}]}, "pops는"),
    ],
)
def test_synth_problems(spec, needle):
    problems = synth_problems(spec, "E99/t")
    assert any(needle in p for p in problems), problems


def test_load_cases_rejects_duplicate_ids(tmp_path):
    for name in ("E1-a.json", "E1-b.json"):
        (tmp_path / name).write_text(json.dumps(_case(id="E1"), ensure_ascii=False), encoding="utf-8")
    with pytest.raises(ValueError, match="겹칩니다"):
        load_cases(tmp_path, ROOT)


# ---------------------------------------------------------------- 합성 스펙 → 트레이스
def test_spec_ret_chain_matches_frozen_boundary(builder):
    """ret gadget 11개·10개 체인은 고정 사례 F3과 같은 경계에서 판정이 갈린다."""
    r11 = _detect(builder.spec_trace("t-11", {"chain": [RET] * 11, "ending": "stop"}))
    r10 = _detect(builder.spec_trace("t-10", {"chain": [RET] * 10, "ending": "stop"}))
    assert (r11["verdict"], r11["chain_len"], r11["checkpoint"]["step"]) == ("ROP", 11, 3)
    assert (r10["verdict"], r10["chain_len"]) == ("정상", 10)


def test_spec_trace_format_and_entries(builder):
    tr = builder.spec_trace("t-fmt", {"chain": [{"addr": "rop_vault+0x4011de", "pops": ["0x404060"]}, RET]})
    assert trace_io.validate(tr) == []
    assert tr.end == {"end": "syscall", "sys": 59} and tr.steps[-1].sys == 59
    first, second = tr.header["entries"]
    assert (first["addr"], first["how"], first["gadget"], first["asm"]) == ("0x4011de", "addr", True, "pop rdi; ret")
    assert second["how"] == "pick" and second["gadget"]
    # 페이지가 바뀐 스텝과 syscall 스텝에는 스냅샷이 있다(수집기와 같은 규칙)
    prev = None
    for s in tr.steps:
        if prev is None or s.pc // 4096 != prev or s.sys is not None:
            assert s.sp is not None and s.stk is not None
        prev = s.pc // 4096
    # 체인 스택(공격 페이로드)은 처음부터 깔려 있다: vuln 복귀 슬롯(FRAME)부터 pop rdi; ret, "/bin/sh",
    # 다음 gadget, execve 착지 주소 순서
    s0 = tr.steps[0]
    assert s0.sp == FRAME - 0x58
    assert s0.stk[11:15] == (0x4011DE, 0x404060, int(second["addr"], 16), builder.syscall_site)
    assert tr.steps[3].pc == 0x4011DE and tr.steps[3].stk is None  # vuln과 같은 페이지 → 체크포인트 아님


def test_nongadget_is_long_and_not_in_db(builder):
    tr = builder.spec_trace("t-long", {"chain": [{"nongadget": {"n_min": 7}}], "ending": "stop"})
    (entry,) = tr.header["entries"]
    assert entry["how"] == "nongadget" and entry["gadget"] is False
    assert len(entry["asm"].split("; ")) >= 7 and entry["asm"].endswith("ret")


def test_ending_none_has_no_landing_step(builder):
    tr = builder.spec_trace("t-none", {"chain": [RET, RET], "ending": "none"})
    picked = [int(e["addr"], 16) for e in tr.header["entries"]]
    assert [s.pc for s in tr.steps[3:]] == picked
    assert tr.end == {"end": "max_steps"}


def test_unknown_rsp_needs_rsp_to(builder):
    with pytest.raises(ValueError, match="rsp_to"):
        builder.spec_trace("t-pivot", {"chain": [{"pick": {"asm": "^pop rsp; ret$"}}]})


@pytest.mark.parametrize("case", load_cases(EXAMPLES, ROOT), ids=lambda c: c["id"])
def test_committed_example_traces_match_spec(builder, case):
    """형식 예시의 traces/extra 파일이 스펙에서 다시 만든 것과 같다(예시가 낡지 않게)."""
    for chk in case["checks"]:
        if "synth" not in chk:
            continue
        on_disk = trace_io.load(ROOT / trace_of(chk))
        fresh = builder.spec_trace(chk["id"], chk["synth"])
        assert (on_disk.header, on_disk.steps, on_disk.end) == (fresh.header, fresh.steps, fresh.end)


# ---------------------------------------------------------------- 실행기
def test_run_extra_on_examples(tmp_path):
    code = run_cases.main(["--cases", (ROOT / EXAMPLES).as_posix(), "--out", str(tmp_path)])
    text = (tmp_path / "compare.md").read_text(encoding="utf-8")
    assert code == 0
    assert "결과: 기대와 같음 4 · 기대와 다름(반례) 0 · 실행 전 0 · 오류 0" in text
    assert "기대와 다른 결과가 없다" in text
    for name in ("ex-ret-11.before.log", "ex-ret-11.after.json", "ex-unit-db.pytest.log"):
        assert (tmp_path / "runs" / name).exists()


def test_run_extra_lists_counterexamples(tmp_path):
    """기대와 다른 결과는 반례 목록(C1…)에 들어가고, 결과 분석의 분류·처리가 함께 나온다(실패 아님)."""
    cases = tmp_path / "cases"
    cases.mkdir()
    case = _case(
        id="E1",
        checks=[
            {"id": "t-miss", "trace": "traces/extra/ex-ret-10.jsonl.gz", "expect": {"verdict": "ROP"}},
            {"id": "t-pending", "synth": {"chain": [RET]}, "expect": {"verdict": "ROP"}},
        ],
    )
    case["결과 분석"] = {"분류": "원논문 한계", "처리": "한계로 기록", "근거": "논문 §IX-C"}
    (cases / "E1-test.json").write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
    out = tmp_path / "out"
    code = run_cases.main(["--cases", str(cases), "--out", str(out)])
    text = (out / "compare.md").read_text(encoding="utf-8")
    assert code == 0
    assert "기대와 같음 0 · 기대와 다름(반례) 1 · 실행 전 1 · 오류 0" in text
    assert "| C1 | E1 `t-miss`: ret 체인 | ROP | 정상, 연쇄 10 — 판정 정상 (기대 ROP) | 원논문 한계 | 한계로 기록 | 논문 §IX-C |" in text
    # 기본 폴더(cases/extra)가 아니므로 만드는 명령에 --cases가 붙는다(지적 12)
    assert f"⏳ 트레이스 없음(`python -m ropecker.synth --extra --cases {cases.resolve().as_posix()} --only E1`)" in text


def test_only_requires_cases():
    with pytest.raises(SystemExit):
        run_cases.main(["--only", "E1"])


# ---------------------------------------------------------------- 리뷰 반영(합성 스택 모델·검사·실행기)
def _ret_mismatches(tr):
    """스냅샷이 있는 ret 스텝에서 스택 맨 위가 다음 pc와 다른 스텝 번호들(스냅샷이 실제 실행과 맞는지)."""
    img = Image.from_header(tr.header, root=ROOT)
    return [
        i
        for i, s in enumerate(tr.steps[:-1])
        if s.stk is not None and img.insn(s.pc).text.startswith("ret") and s.stk[0] != tr.steps[i + 1].pc
    ]


def test_call_ind_return_address_must_be_discarded(builder):
    """call*이 쌓은 복귀 주소를 꺼내 버리지 않고 바로 ret하는 스펙은 만들 수 없다(지적 1)."""
    with pytest.raises(ValueError, match="복귀 주소"):
        builder.spec_trace("t-call-bad", {"chain": [RET, {"pick": {"asm": "^call rax$"}}, RET, RET], "ending": "stop"})


def test_call_ind_snapshots_follow_execution(builder):
    """call* 뒤 pop으로 복귀 주소를 버리면 만들어지고, 스냅샷은 시점에 맞는 스택을 보인다."""
    spec = {"chain": [RET, {"pick": {"asm": "^call rax$"}}, {"pick": {"asm": "^pop rbx; ret$"}}, RET, RET], "ending": "stop"}
    tr = builder.spec_trace("t-call", spec)
    assert _ret_mismatches(tr) == []
    call = int(tr.header["entries"][1]["addr"], 16)
    target = int(tr.header["entries"][2]["addr"], 16)
    after_call = next(s for s in tr.steps if s.pc == target)  # 새 페이지 진입이라 스냅샷이 있다
    assert after_call.stk[0] == call + 2  # call rax(2바이트)가 쌓은 복귀 주소
    before = next(s for s in tr.steps if s.stk is not None and s.pc == int(tr.header["entries"][0]["addr"], 16))
    assert before.stk[0] == call  # 그보다 앞 스냅샷에는 쌓기 전 값(페이로드)이 보인다


def test_pivot_back_onto_used_slot_is_rejected(builder):
    spec = {"chain": [RET, {"pick": {"asm": "^pop rsp; ret$"}, "rsp_to": hex(FRAME + 8)}, RET]}
    with pytest.raises(ValueError, match="서로 다른 값"):
        builder.spec_trace("t-pivot-bad", spec)


def test_pivot_to_new_stack(builder):
    spec = {"chain": [RET, {"pick": {"asm": "^pop rsp; ret$"}, "rsp_to": "0x7ffff0001000"}, RET, RET]}
    tr = builder.spec_trace("t-pivot", spec)
    assert _ret_mismatches(tr) == []
    assert any(s.sp is not None and 0x7FFFF0001000 <= s.sp < 0x7FFFF0002000 for s in tr.steps)


@pytest.mark.parametrize(
    "entry, needle",
    [
        ({"pick": {"asm": "^pop rdi; ret$"}, "pops": ["0x1", "0x2"]}, "pops 값 1개가 남았습니다"),
        ({"pick": {"asm": "^ret$"}, "rsp_to": "0x7ffff0001000"}, "rsp_to를 쓸 명령"),
        ({"pick": {"asm": "^ret$"}, "sys": 59}, "syscall이 없습니다"),
    ],
)
def test_unused_entry_options_are_errors(builder, entry, needle):
    with pytest.raises(ValueError, match=needle):
        builder.spec_trace("t-opt", {"chain": [entry]})


def test_pops_accept_module_notation(builder):
    tr = builder.spec_trace("t-pops", {"chain": [{"pick": {"asm": "^pop rdi; ret$"}, "pops": ["rop_vault+0x404060"]}, RET]})
    assert tr.steps[0].stk[12] == 0x404060  # vuln 복귀 슬롯(FRAME) 다음 칸 = pop rdi가 꺼낼 값


@pytest.mark.parametrize(
    "code, kind, delta, writes",
    [
        (b"\x58", "pop", 8, ()),  # pop rax
        (b"\xf3\x48\x0f\xb8\xc3", "none", 0, ()),  # popcnt rax, rbx — pop이 아님(E3)
        (b"\x48\x83\xc4\x18", "adjust", 0x18, ()),  # add rsp, 0x18
        (b"\x48\x89\x44\x24\x08", "none", 0, (8,)),  # mov [rsp+8], rax — 실행 중 스택 쓰기
        (b"\xc9", "unknown", 0, ()),  # leave
        (b"\x5c", "unknown", 0, ()),  # pop rsp
    ],
)
def test_stack_effect_is_independent_of_gadget_db(code, kind, delta, writes):
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    eff = _stack_effect(next(md.disasm(code, 0x1000)), "t")
    assert (eff.kind, eff.delta, eff.writes) == (kind, delta, writes)


def test_sixteen_bit_stack_ops_are_rejected():
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    for code in (b"\x66\x58", b"\x66\x50"):  # pop ax, push ax
        with pytest.raises(ValueError, match="16비트"):
            _stack_effect(next(md.disasm(code, 0x1000)), "t")


@pytest.mark.parametrize("folder", [EXTRA_DIR, EXAMPLES])
def test_committed_synth_traces_match_their_spec(folder):
    """커밋된 합성 트레이스가 지금 사례 파일의 스펙으로 만든 것인지(스펙만 고치고 다시 만들지 않은 경우를 잡음)."""
    for case in load_cases(folder, ROOT):
        for chk in case["checks"]:
            path = ROOT / trace_of(chk)
            if "synth" in chk and path.exists():
                assert trace_header(path).get("spec") == chk["synth"], f"{case['id']}/{chk['id']}"


def test_stale_synth_trace_is_flagged(tmp_path):
    """스펙을 바꿨는데 트레이스는 예전 것이면 실행기는 ⚠️로 표시하고 1로 끝난다(지적 5)."""
    cases = tmp_path / "cases"
    cases.mkdir()
    case = _case(id="E1", checks=[{"id": "ex-ret-11", "synth": {"chain": [RET] * 5}, "expect": {"verdict": "정상"}}])
    (cases / "E1-stale.json").write_text(json.dumps(case, ensure_ascii=False), encoding="utf-8")
    code = run_cases.main(["--cases", str(cases), "--out", str(tmp_path / "out")])
    text = (tmp_path / "out" / "compare.md").read_text(encoding="utf-8")
    assert code == 1
    assert "⚠️ 스펙과 다른 옛 트레이스" in text and "오류 1" in text
    assert synth.main(["--extra", "--cases", str(cases)]) == 1  # 합성 도구도 덮어쓰지 않고 경고


def test_synth_cli_guards():
    with pytest.raises(SystemExit):
        synth.main(["--extra", "--force"])  # --force는 --only와 함께
    assert synth.main(["--extra", "--cases", str(ROOT / EXAMPLES), "--only", "E99"]) == 2


JUNIT = '<testsuites><testsuite name="pytest" tests="{t}" failures="{f}" errors="{e}" skipped="{s}"/></testsuites>'


@pytest.mark.parametrize(
    "counts, want_pass, mark",
    [
        (None, True, "⚠️ 오류"),
        ({"tests": 0, "failures": 0, "errors": 0, "skipped": 0}, True, "⚠️ 오류"),
        ({"tests": 1, "failures": 0, "errors": 1, "skipped": 0}, False, "⚠️ 오류"),  # 준비 오류는 '실패'가 아니다
        ({"tests": 1, "failures": 0, "errors": 0, "skipped": 1}, True, "⚠️ 오류"),  # skip은 '통과'가 아니다
        ({"tests": 1, "failures": 0, "errors": 0, "skipped": 0}, True, "✅ 기대와 같음"),
        ({"tests": 1, "failures": 1, "errors": 0, "skipped": 0}, True, "❌ 기대와 다름"),
        ({"tests": 1, "failures": 1, "errors": 0, "skipped": 0}, False, "✅ 기대와 같음"),
    ],
)
def test_unit_check_status(counts, want_pass, mark):
    assert run_cases.unit_status(counts, want_pass)[1] == mark


def test_junit_counts():
    assert run_cases.junit_counts(JUNIT.format(t=2, f=1, e=0, s=1)) == {"tests": 2, "failures": 1, "errors": 0, "skipped": 1}


def test_only_runs_go_to_an_uncommitted_folder():
    assert run_cases.extra_out(None, None) == ROOT / "results" / "w13"
    assert run_cases.extra_out(None, {"E1"}) == ROOT / "results" / "w13-only.tmp"
    assert run_cases.extra_out(Path("x"), {"E1"}) == Path("x")
