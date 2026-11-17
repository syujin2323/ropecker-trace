"""트레이스 v1 읽기·쓰기·검증 (docs/design.md "트레이스 v1").

파일은 JSON Lines이고, 첫 바이트가 gzip 매직(1f 8b)이면 확장자와 상관없이 압축으로 읽는다.
그래서 보고서의 `--trace t.log`처럼 아무 이름이어도 된다.
"""

from __future__ import annotations

import gzip
import io
import json
from pathlib import Path

from .model import TRACE_FMT, TRACE_V, Step, Trace, hx, parse_addr

_GZIP_MAGIC = b"\x1f\x8b"


def _open_text(path: Path, mode: str):
    if "r" in mode:
        with open(path, "rb") as f:
            magic = f.read(2)
        if magic == _GZIP_MAGIC:
            return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8")
        return open(path, encoding="utf-8")
    if path.suffix == ".gz":
        # 파일 이름·시각을 헤더에 넣지 않아(mtime=0) 같은 내용이면 같은 바이트가 나온다(git diff 잡음 방지)
        raw = gzip.GzipFile(filename="", mode="wb", fileobj=open(path, "wb"), mtime=0)
        return io.TextIOWrapper(_ClosingGzip(raw), encoding="utf-8", newline="\n")
    return open(path, "w", encoding="utf-8", newline="\n")


class _ClosingGzip(io.RawIOBase):
    """GzipFile을 닫을 때 밑에 있는 파일 객체도 함께 닫는다."""

    def __init__(self, gz: gzip.GzipFile):
        self._gz = gz

    def writable(self) -> bool:
        return True

    def write(self, b) -> int:
        return self._gz.write(b)

    def close(self) -> None:
        if not self.closed:
            fileobj = self._gz.fileobj
            self._gz.close()
            if fileobj is not None:
                fileobj.close()
        super().close()


def _step_from_json(obj: dict) -> Step:
    stk = obj.get("stk")
    return Step(
        pc=parse_addr(obj["pc"]),
        sp=parse_addr(obj["sp"]) if obj.get("sp") is not None else None,
        stk=tuple(parse_addr(v) for v in stk) if stk is not None else None,
        sys=obj.get("sys"),
    )


def _step_to_json(step: Step) -> dict:
    obj: dict = {"pc": hx(step.pc)}
    if step.sp is not None:
        obj["sp"] = hx(step.sp)
    if step.stk is not None:
        obj["stk"] = [hx(v) for v in step.stk]
    if step.sys is not None:
        obj["sys"] = step.sys
    return obj


def load(path: str | Path) -> Trace:
    """트레이스 파일을 읽는다. 형식이 깨졌으면 ValueError."""
    path = Path(path)
    with _open_text(path, "r") as f:
        lines = [ln for ln in (raw.strip() for raw in f) if ln]
    if not lines:
        raise ValueError(f"{path}: 빈 파일")
    header = json.loads(lines[0])
    if header.get("fmt") != TRACE_FMT:
        raise ValueError(f"{path}: 트레이스 헤더가 아님(fmt={header.get('fmt')!r})")
    if header.get("v") != TRACE_V:
        raise ValueError(f"{path}: 지원하지 않는 버전 v={header.get('v')!r}")
    steps: list[Step] = []
    end: dict = {"end": "max_steps"}
    for no, line in enumerate(lines[1:], start=2):
        obj = json.loads(line)
        if "end" in obj:
            end = obj
            if no != len(lines):
                raise ValueError(f"{path}:{no}: end 행 뒤에 내용이 있음")
            break
        try:
            steps.append(_step_from_json(obj))
        except (KeyError, ValueError) as e:
            raise ValueError(f"{path}:{no}: 스텝 형식 오류: {e}") from e
    return Trace(header=header, steps=steps, end=end)


def dump(tr: Trace, path: str | Path) -> None:
    """트레이스를 쓴다. 경로가 .gz로 끝나면 압축한다."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _open_text(path, "w") as f:
        f.write(json.dumps(tr.header, ensure_ascii=False) + "\n")
        for step in tr.steps:
            f.write(json.dumps(_step_to_json(step)) + "\n")
        f.write(json.dumps(tr.end, ensure_ascii=False) + "\n")


def validate(tr: Trace) -> list[str]:
    """형식 문제 목록(비어 있으면 정상). 분석 전에 CLI가 호출한다."""
    errors: list[str] = []
    h = tr.header
    modules = h.get("modules")
    if not isinstance(modules, list) or not modules:
        errors.append("header.modules가 비어 있음")
    else:
        for i, m in enumerate(modules):
            for key in ("name", "path", "sha256", "base"):
                if key not in m:
                    errors.append(f"header.modules[{i}]에 {key} 없음")
    if "collector" not in h:
        errors.append("header.collector 없음")
    if not tr.steps:
        errors.append("스텝이 하나도 없음")
    for i, s in enumerate(tr.steps):
        if (s.sp is None) != (s.stk is None):
            errors.append(f"스텝 {i}: sp와 stk는 함께 있어야 함")
            break
    if tr.end.get("end") not in {"exit", "signal", "syscall", "max_steps"}:
        errors.append(f"end 값이 올바르지 않음: {tr.end.get('end')!r}")
    return errors
