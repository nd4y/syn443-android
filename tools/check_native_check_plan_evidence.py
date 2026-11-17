"""Require public-vector-bound check-plan outcomes from one real Go JSON stream."""
import json
from pathlib import Path
import re
import sys

from check_native_protocol_evidence import (BRIDGE, MAX_BYTES, _closing, _function,
                                            _invalid_constant,
                                            _positions, _tokens, _unique_object)

CATEGORIES = (
    ('TestCheckPlanV2ValidSharedVectors', 'ValidCases', 'validCases', 9, {'name', 'profile', 'sha256'}),
    ('TestCheckPlanV2InvalidSharedVectors', 'InvalidCases', 'invalidCases', 37, {'name', 'profile'}),
    ('TestCheckPlanV2InvalidRawSharedVectors', 'InvalidRawCases', 'invalidRawCases', 6, {'name', 'raw'}),
    ('TestCheckPlanV2TruthSharedVectors', 'TruthCases', 'truthCases', 51, {'name', 'profile', 'results', 'expected', 'visited', 'leafStates'}),
    ('TestCheckPlanV2LegacyHashSharedVectors', 'LegacyCases', 'legacyCases', 1, {'name', 'checks', 'sha256'}),
)
RUNTIME_ROOTS = (
    'TestCheckPlanV2MetadataCannotDowngradeOrMutateApprovedProfiles',
    'TestCheckPlanV2OrdinaryRequiresExactApprovedConcreteProgram',
    'TestCheckPlanV2VariablePathsAndMissingLeaseCannotDispatch',
    'TestCheckPlanV2AdmissionCountsAllDeclaredAlternativeLeaves',
    'TestCheckPlanV2GlobalAbortAndLeafWitnessAreIndependent',
    'TestCheckPlanV2AdaptiveTwoHopAlternativesNeverReachTargetDirectly',
    'TestCheckPlanV2AdaptiveOriginalDeadlinePrecedesFirstIOAndFinalProof',
    'TestCheckPlanV2AdaptiveProofBindsWholeProgramAndExistingReceiptTTL',
    'TestCheckPlanV2ProfileTimeoutClosesRealReadAndSkipsLaterStage',
    'TestCheckPlanV2MandatoryExitGateWithdrawsOnlyItsActiveGroup',
    'TestCheckPlanV2AdaptiveRuntimeAndHubRetainMandatoryCountryGate',
    'TestCheckPlanV2OwnerReportsArePassiveBoundedAndFresh',
)
ROOTS = tuple(row[0] for row in CATEGORIES) + RUNTIME_ROOTS
SUBCASES = {
    'TestCheckPlanV2AdaptiveOriginalDeadlinePrecedesFirstIOAndFinalProof':
        ('phase', ('before-first', 'after-connection', 'lease', 'scope', 'cancel')),
    'TestCheckPlanV2MandatoryExitGateWithdrawsOnlyItsActiveGroup':
        ('method', ('https_exit_country', 'https_exit_ip')),
}
FIXTURE_NAME = 'route-check-profile-v2-vectors.json'


def fixture_cases(raw, copied):
    assert isinstance(raw, str) and 0 < len(raw.encode('utf-8')) <= 524288, 'Invalid check-plan vector size'
    assert copied == raw, 'Native check-plan fixture differs from the public contract'
    try:
        data = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
    except (ValueError, TypeError) as error:
        raise AssertionError('Malformed check-plan contract') from error
    assert isinstance(data, dict) and set(data) == {'schemaVersion'} | {row[2] for row in CATEGORIES}, 'Foreign check-plan contract fields'
    assert type(data['schemaVersion']) is int and data['schemaVersion'] == 1, 'Invalid check-plan contract version'
    required = set(ROOTS)
    for root, _field, key, count, fields in CATEGORIES:
        cases = data[key]
        assert isinstance(cases, list) and len(cases) == count, 'Check-plan contract inventory drift'
        names = set()
        for case in cases:
            assert isinstance(case, dict) and set(case) == fields, 'Foreign check-plan case fields'
            name = case['name']
            assert isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_-]+', name) and len(name) <= 128 and name not in names, 'Duplicate or rewritten check-plan case'
            names.add(name)
            if 'profile' in fields:
                assert isinstance(case['profile'], dict), 'Invalid profile fixture'
            if 'sha256' in fields:
                assert isinstance(case['sha256'], str) and re.fullmatch(r'[a-f0-9]{64}', case['sha256']), 'Invalid vector hash'
            if 'raw' in fields:
                assert isinstance(case['raw'], str), 'Invalid raw profile fixture'
            if 'checks' in fields:
                assert isinstance(case['checks'], list), 'Invalid legacy fixture'
            if 'results' in fields:
                assert case['expected'] in {'TRUE', 'FALSE', 'UNKNOWN'}, 'Invalid truth outcome'
                assert isinstance(case['visited'], list) and all(isinstance(item, str) for item in case['visited']), 'Invalid truth traversal'
                for field in ('results', 'leafStates'):
                    assert isinstance(case[field], dict) and all(isinstance(item, str) and value in {'TRUE', 'FALSE', 'UNKNOWN', 'SKIPPED'} for item, value in case[field].items()), 'Invalid truth leaf metadata'
            required.add(root + '/' + name)
    for root, (_variable, leaves) in SUBCASES.items():
        required.update(root + '/' + leaf for leaf in leaves)
    assert len(required) == 128, 'Check-plan evidence inventory drift'
    return frozenset(required)


def source_bindings(source, runtime_source, fixture, copied):
    required = fixture_cases(fixture, copied)
    tokens, runtime = _tokens(source), _tokens(runtime_source)
    declared = []
    for stream in (tokens, runtime):
        for index, token in enumerate(stream[:-1]):
            if token == 'func' and stream[index + 1].startswith('TestCheckPlanV2'):
                declared.append(stream[index + 1])
    assert len(declared) == len(set(declared)) and set(declared) == set(ROOTS), 'Check-plan root source inventory drift'
    assert tokens.count('"testdata/' + FIXTURE_NAME + '"') == 1, 'Shared check-plan fixture path drift'
    for root, field, _key, _count, _fields in CATEGORIES:
        body = _function(tokens, root)
        loop = ['for', '_', ',', 'tc', ':', '=', 'range', 'readCheckPlanShared', '(', 't', ')', '.', field, '{']
        matches = _positions(body, loop)
        assert len(matches) == 1, 'Shared-vector loop escaped its source category'
        start = matches[0] + len(loop) - 1
        end = _closing(body, start)
        runs = _positions(body, ['t', '.', 'Run', '('])
        assert len(runs) == 1 and start < runs[0] < end, 'Shared-vector subtests are not flat'
        call = ['t', '.', 'Run', '(', 'tc', '.', 'Name', ',', 'func', '(', 't', '*', 'testing', '.', 'T', ')', '{']
        assert body[runs[0]:runs[0] + len(call)] == call, 'Shared-vector subtest name drift'
    for root in RUNTIME_ROOTS:
        body = _function(runtime, root)
        runs = _positions(body, ['t', '.', 'Run', '('])
        if root not in SUBCASES:
            assert not runs, 'Unregistered runtime subcases'
            continue
        variable, values = SUBCASES[root]
        # Existing protocol literal lexer intentionally accepts only hyphens;
        # these method names additionally contain underscores, so validate this
        # one bounded table using the same Go token stream directly.
        prefix = ['for', '_', ',', variable, ':', '=', 'range', '[', ']', 'string', '{']
        tables = _positions(body, prefix)
        assert len(tables) == 1, 'Missing runtime boundary table'
        start = tables[0] + len(prefix) - 1
        end = _closing(body, start)
        expected = []
        for value in values:
            expected += [json.dumps(value), ',']
        actual = body[start + 1:end]
        assert actual in (expected, expected[:-1]), 'Runtime boundary source table drift'
        assert end + 1 < len(body) and body[end + 1] == '{', 'Missing runtime boundary body'
        bounds = end + 1, _closing(body, end + 1)
        call = ['t', '.', 'Run', '(', variable, ',', 'func', '(', 't', '*', 'testing', '.', 'T', ')', '{']
        assert len(runs) == 1 and bounds[0] < runs[0] < bounds[1] and body[runs[0]:runs[0] + len(call)] == call, 'Runtime subcase name drift'
    return required


def verify(lines, source, runtime_source, fixture, copied):
    required = source_bindings(source, runtime_source, fixture, copied)
    states, completed, started, size = {}, False, False, 0
    for line in lines:
        assert isinstance(line, str), 'Invalid native event input'
        size += len(line.encode('utf-8'))
        assert size <= MAX_BYTES and len(line) <= 1024 * 1024, 'Unbounded native check-plan evidence'
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        except (ValueError, TypeError) as error:
            raise AssertionError('Malformed native check-plan event') from error
        assert isinstance(row, dict), 'Invalid native event'
        action, package, imported, test = (row.get(key) for key in ('Action', 'Package', 'ImportPath', 'Test'))
        assert isinstance(action, str) and action, 'Invalid native action'
        for key in ('Package', 'ImportPath', 'Test'):
            assert key not in row or isinstance(row[key], str) and row[key], 'Invalid native metadata'
        assert package is not None or imported is not None, 'Missing native package'
        target = test is not None and any(test == root or test.startswith(root + '/') for root in ROOTS)
        if target:
            assert test in required and package == BRIDGE and imported in (None, BRIDGE), 'Foreign or unbound check-plan outcome'
        if package != BRIDGE and imported != BRIDGE:
            continue
        assert package in (None, BRIDGE) and imported in (None, BRIDGE), 'Ambiguous native package'
        assert not completed, 'Native event after package completion'
        assert action not in {'fail', 'skip', 'error', 'build-fail'} and row.get('Error') in (None, ''), 'Bridge regression failed or skipped'
        if action == 'build-output':
            assert test is None and not started and not states, 'Late or test-bound build metadata'
            continue
        assert package == BRIDGE, 'Test lifecycle requires actual bridge package'
        assert action in {'start', 'run', 'pause', 'cont', 'pass', 'output'}, 'Unknown bridge action'
        if action == 'start':
            assert test is None and not started and not states, 'Duplicate or late bridge start'
            started = True
            continue
        assert started, 'Bridge event before package start'
        if test is None:
            if action == 'pass':
                assert required <= states.keys() and all(value == 'passed' for value in states.values()), 'Incomplete bridge package'
                completed = True
            else:
                assert action == 'output', 'Invalid bridge package order'
        elif action == 'run':
            assert test not in states and len(states) < 65536, 'Duplicate or unbounded bridge test'
            if target and test not in ROOTS:
                assert states.get(test.split('/')[0]) == 'running', 'Check-plan leaf outside running parent'
            states[test] = 'running'
        elif action == 'pass':
            assert states.get(test) == 'running', 'Bridge pass without one run'
            if test in ROOTS:
                assert all(states.get(name) == 'passed' for name in required if name.startswith(test + '/')), 'Check-plan parent before its leaves'
            states[test] = 'passed'
        elif action in {'pause', 'cont'}:
            assert states.get(test) == ('running' if action == 'pause' else 'paused'), 'Invalid bridge parallel event order'
            states[test] = 'paused' if action == 'pause' else 'running'
        else:
            assert action == 'output' and test in states, 'Bridge output without test start'
    assert started and completed and required <= states.keys() and all(states[name] == 'passed' for name in required), 'Missing actual check-plan outcomes or completion'
    return len(required)


def main():
    assert len(sys.argv) == 2, 'Expected one actual native JSON stream'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= MAX_BYTES, 'Missing or unbounded check-plan evidence'
    root = Path(__file__).resolve().parent.parent
    source = (root / 'native/bridge/route_check_profile_test.go').read_text(encoding='utf-8')
    runtime = (root / 'native/bridge/route_check_profile_runtime_test.go').read_text(encoding='utf-8')
    fixture = (root / 'contracts/v1' / FIXTURE_NAME).read_bytes()
    copied = (root / 'native/build/bridge/testdata' / FIXTURE_NAME).read_bytes()
    assert fixture == copied, 'Native public check-plan fixture bytes differ'
    with path.open(encoding='utf-8') as stream:
        count = verify(stream, source, runtime, fixture.decode('utf-8'), copied.decode('utf-8'))
    print(f'Native check-plan evidence: {count} actual ordered passes, public vectors and one bridge completion')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, UnicodeError, ValueError, TypeError):
        raise SystemExit('Native check-plan evidence invalid')
