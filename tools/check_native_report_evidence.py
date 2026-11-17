"""Require source-bound NetBird report and bridge outcomes in each Go stream."""
import json
from pathlib import Path
import sys

from check_native_protocol_evidence import _tokens, _function, _unique_object, _invalid_constant

MODULE = 'io.syn443/engine-netbird'
BRIDGE = 'io.syn443/bridge'
MODULE_ROOTS = frozenset({
    'TestReportViewStrictRequestsCannotMutateOwnerOrCallSDK',
    'TestReportViewPeersPageRealRosterWithoutWholeSliceRetention',
    'TestReportViewDiagnosticTargetsAndCoverageRemainBounded',
    'TestReportViewPartialCancelledAndInvalidTargetsNeverClaimComplete',
    'TestReportViewUTF8IdentifiersAndNumericBoundsAreOwned',
    'TestReportViewConcurrentSectionsClampAndEchoIndependentRequests',
    'TestReportViewDeferredFallbackPreservesCriticalConnectionHeader',
    'TestReportViewBlockedSnapshotAndCancelledWorkerRetainAdmission',
})
BRIDGE_ROOTS = frozenset({
    'TestNetBirdViewBridgeRejectsInactiveRuntimeWithoutStartingOwner',
    'TestNetBirdViewBridgeRetainsLeaseExpiryAndNoOwnerRecovery',
})
MAX_BYTES = 64 * 1024 * 1024


def source_bindings(module_source, bridge_source):
    for source, required in ((module_source, MODULE_ROOTS), (bridge_source, BRIDGE_ROOTS)):
        tokens = _tokens(source)
        actual = [tokens[i + 1] for i in range(len(tokens) - 2)
                  if tokens[i] == 'func' and tokens[i + 1].startswith('Test') and tokens[i + 2] == '(']
        assert len(actual) == len(set(actual)) == len(required) and set(actual) == required, 'Report source inventory drift'
        for name in required:
            assert _function(tokens, name), 'Empty report test root'
    return {MODULE: MODULE_ROOTS, BRIDGE: BRIDGE_ROOTS}


def verify(lines, module_source, bridge_source):
    required = source_bindings(module_source, bridge_source)
    all_roots = MODULE_ROOTS | BRIDGE_ROOTS
    states = {package: {} for package in required}
    started, completed, size = set(), set(), 0
    for line in lines:
        assert isinstance(line, str), 'Invalid report evidence input'
        size += len(line.encode('utf-8'))
        assert size <= MAX_BYTES and len(line) <= 1024 * 1024, 'Unbounded report evidence'
        if not line.strip():
            continue
        row = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        assert isinstance(row, dict), 'Invalid report event'
        action, package, imported, test = (row.get(key) for key in ('Action', 'Package', 'ImportPath', 'Test'))
        assert isinstance(action, str) and action, 'Invalid report action'
        for key in ('Package', 'ImportPath', 'Test'):
            assert key not in row or isinstance(row[key], str) and row[key], 'Invalid report metadata'
        assert package is not None or imported is not None, 'Missing report package'
        root = test.split('/')[0] if test else None
        if root in all_roots:
            expected = MODULE if root in MODULE_ROOTS else BRIDGE
            assert package == expected and imported in (None, expected), 'Foreign report outcome'
        target = package if package in required else imported if imported in required else None
        if target is None:
            continue
        assert package in (None, target) and imported in (None, target), 'Ambiguous report package'
        assert target not in completed, 'Report event after package completion'
        assert action not in {'fail', 'skip', 'error', 'build-fail'} and row.get('Error') in (None, ''), 'Report package failed or skipped'
        if action == 'build-output':
            assert test is None and target not in started, 'Late report build output'
            continue
        assert package == target and action in {'start', 'run', 'pause', 'cont', 'pass', 'output'}, 'Invalid report lifecycle'
        if action == 'start':
            assert test is None and target not in started and not states[target], 'Duplicate report package start'
            started.add(target)
            continue
        assert target in started, 'Report event before package start'
        state = states[target]
        if test is None:
            if action == 'pass':
                assert required[target] <= state.keys() and all(value == 'passed' for value in state.values()), 'Incomplete report package'
                completed.add(target)
            else:
                assert action == 'output', 'Invalid report package terminal'
        elif action == 'run':
            assert test not in state and len(state) < 65536, 'Duplicate or unbounded report outcomes'
            if root in all_roots and '/' in test:
                assert state.get(root) == 'running', 'Report leaf outside its root lifetime'
            state[test] = 'running'
        elif action == 'pass':
            assert state.get(test) == 'running', 'Report pass without one start'
            if root == test and root in all_roots:
                assert all(value == 'passed' for name, value in state.items() if name.startswith(root + '/')), 'Report root passed before its leaves'
            state[test] = 'passed'
        elif action in {'pause', 'cont'}:
            assert state.get(test) == ('running' if action == 'pause' else 'paused'), 'Invalid report parallel lifecycle'
            state[test] = 'paused' if action == 'pause' else 'running'
        else:
            assert action == 'output' and test in state, 'Report output without start'
    assert completed == started == set(required), 'Missing actual report package completion'
    return {package: len(roots) for package, roots in required.items()}


def main():
    assert len(sys.argv) == 2, 'Expected one native report JSON stream'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= MAX_BYTES, 'Missing native report evidence'
    root = Path(__file__).resolve().parent.parent
    sources = [(root / name).read_text(encoding='utf-8') for name in (
        'native/engine-netbird/report_view_test.go', 'native/bridge/netbird_view_test.go')]
    with path.open(encoding='utf-8') as stream:
        result = verify(stream, *sources)
    print('Native report evidence:8 module and2 bridge roots, ordered passes and both package completions')
    return result


if __name__ == '__main__':
    main()
