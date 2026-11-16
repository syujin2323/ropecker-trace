"""공통 pytest 설정.

아직 구현되지 않은 함수(NotImplementedError)를 부르는 테스트는 실패가 아니라 xfail("미구현")로 표시한다.
그래서 레인이 구현을 채우면 마커를 고치지 않아도 그 테스트가 저절로 진짜 pass/fail로 바뀐다.
NotImplementedError 말고 다른 예외는 그대로 실패다.
"""

import pytest


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(item, call):
    outcome = yield
    report = outcome.get_result()
    if report.when == "call" and call.excinfo is not None and call.excinfo.errisinstance(NotImplementedError):
        report.outcome = "skipped"
        report.wasxfail = f"미구현: {call.excinfo.value}"
