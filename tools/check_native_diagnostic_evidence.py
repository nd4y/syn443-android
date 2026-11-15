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
PATH_REQUIRED = {
    'TestPrivateCandidateRegistryClonesParentAndNeverBorrowsDefault',
    'TestPrivateCandidateFailureOwnsPartialObjectsAndClosesInReverse',
    'TestPrivateCandidateRejectsInvalidPathsAndClosePanicCannotOrphanEarlierNodes',
    'TestPrivatePoolRealTrafficHoldAndConfiguredCapacity',
    'TestPrivatePoolBlockedConstructionCannotPublishAfterScopeChange',
    'TestPrivatePoolRetirementFailureAndBlockedCloseKeepReservations',
    'TestPrivateTrafficRealTCPLeaseAndGracefulDrain',
    'TestPrivateTrafficPacketsAndLateReadCannotOutliveContext',
    'TestPrivateTrafficPartialDialPanicAndLateOwnerKeepCapacity',
}


def verify(lines, required=REQUIRED, expected_package='io.syn443/engine-netbird'):
    state = {}
    for line in lines:
        if not line.strip():
            continue
        row = json.loads(line)
        assert isinstance(row, dict), 'Invalid native test record'
        action, package, test = (row.get(k) for k in ('Action', 'Package', 'Test'))
        assert isinstance(action, str) and isinstance(package, str), 'Invalid native test metadata'
        assert test is None or isinstance(test, str), 'Invalid native test name'
        if package != expected_package or test not in required or action not in {'run', 'pass', 'fail', 'skip'}:
            continue
        if action == 'run':
            assert test not in state, 'Duplicate required native test'
            state[test] = 'running'
        else:
            assert action == 'pass' and state.get(test) == 'running', 'Required native regression failed, skipped or missing its start'
            state[test] = 'passed'
    assert state == {name: 'passed' for name in required}, 'Missing required native regression outcomes'
    return len(state)


if __name__ == '__main__':
    assert sys.argv[2:] in ([], ['--path-candidates']), 'Unsupported evidence mode'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= 64 * 1024 * 1024, 'Missing or unbounded native test evidence'
    with path.open(encoding='utf-8') as source:
        count = verify(source, PATH_REQUIRED, 'io.syn443/bridge') if sys.argv[2:] else verify(source)
    print(f'Native regressions: {count} actual passes, zero failed/skipped/missing cases')
