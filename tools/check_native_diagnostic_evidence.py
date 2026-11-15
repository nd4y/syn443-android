"""Require actual native diagnostic regression outcomes, independently of build success."""
import json
from pathlib import Path
import sys

REQUIRED = {
    'TestLocalDiagnosticCacheProgressDoesNotWaitForBlockedSdkRoster',
    'TestDiagnosticCacheCannotBorrowTheGlobalReplacementOutbound',
    'TestDiagnosticCacheCannotPublishAfterStopWhileLocalReadIsPending',
    'TestBlockedDiagnosticRosterReportsTimeoutWithoutReplacementWorkersOrLateSuccess',
    'TestDiagnosticCancellationBeforeRosterReturnsCannotStartLateProbes',
}


def verify(lines):
    state = {}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid native test record'
        action, package, test = (row.get(k) for k in ('Action', 'Package', 'Test'))
        assert isinstance(action, str) and isinstance(package, str), 'Invalid native test metadata'
        assert test is None or isinstance(test, str), 'Invalid native test name'
        if package != 'io.syn443/engine-netbird' or test not in REQUIRED or action not in {'run', 'pass', 'fail', 'skip'}:
            continue
        if action == 'run':
            assert test not in state, 'Duplicate required native test'
            state[test] = 'running'
        else:
            assert action == 'pass' and state.get(test) == 'running', 'Required native regression failed, skipped or missing its start'
            state[test] = 'passed'
    assert state == {name: 'passed' for name in REQUIRED}, 'Missing required native diagnostic outcomes'
    return len(state)


if __name__ == '__main__':
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64 * 1024 * 1024, 'Missing or unbounded native test evidence'
    with path.open(encoding='utf-8') as source:
        count = verify(source)
    print(f'Native diagnostic regressions: {count} actual passes, zero failed/skipped/missing cases')
