"""Require source-bound VLESS/XHTTP outcomes from one actual Go JSON stream."""
import json
from pathlib import Path
import re
import sys

BRIDGE = 'io.syn443/bridge'
POSITIVE_ROOT = 'TestRegisteredVLESSTLSTransportsActualPayloadAndDetour'
NEGATIVE_ROOT = 'TestRegisteredXHTTPAuthorityFailuresCannotReachTargetDirectly'
POSITIVE_TRANSPORTS = ('tls', 'ws', 'grpc', 'xhttp-h2', 'xhttp-h3', 'xhttp-packet-up', 'xhttp-auto', 'xhttp-stream-up')
XHTTP_TRANSPORTS = ('xhttp-h2', 'xhttp-h3', 'xhttp-packet-up', 'xhttp-auto', 'xhttp-stream-up')
FAILURES = ('uuid', 'certificate', 'server-name', 'refused')
MAX_BYTES = 64 * 1024 * 1024


def required_cases():
    return frozenset({POSITIVE_ROOT, NEGATIVE_ROOT} |
                     {POSITIVE_ROOT + '/' + transport for transport in POSITIVE_TRANSPORTS} |
                     {NEGATIVE_ROOT + '/' + transport + '/' + failure
                      for transport in XHTTP_TRANSPORTS for failure in FAILURES})


def _tokens(source):
    """Only lex Go source; comments and quoted fixture text cannot forge bindings."""
    assert isinstance(source, str) and 0 < len(source.encode('utf-8')) <= 262144, 'Invalid protocol source size'
    result, offset = [], 0
    while offset < len(source):
        char = source[offset]
        if char.isspace():
            offset += 1
            continue
        if source.startswith('//', offset):
            end = source.find('\n', offset + 2)
            offset = len(source) if end < 0 else end + 1
            continue
        if source.startswith('/*', offset):
            end = source.find('*/', offset + 2)
            assert end >= 0, 'Unclosed protocol source comment'
            offset = end + 2
            continue
        start = offset
        if char in ('"', "'", '`'):
            offset += 1
            while offset < len(source) and source[offset] != char:
                if char != '`' and source[offset] == '\\':
                    offset += 1
                offset += 1
            assert offset < len(source), 'Unclosed protocol source literal'
            offset += 1
        elif char.isascii() and (char.isalnum() or char == '_'):
            offset += 1
            while offset < len(source) and source[offset].isascii() and (source[offset].isalnum() or source[offset] == '_'):
                offset += 1
        else:
            offset += 1
        result.append(source[start:offset])
        assert len(result) <= 65536, 'Unbounded protocol source tokens'
    return result


def _positions(tokens, pattern):
    return [index for index in range(len(tokens) - len(pattern) + 1)
            if tokens[index:index + len(pattern)] == pattern]


def _closing(tokens, start):
    assert tokens[start] == '{', 'Missing protocol source block'
    depth = 0
    for index in range(start, len(tokens)):
        if tokens[index] == '{':
            depth += 1
            assert depth <= 64, 'Unbounded protocol source nesting'
        elif tokens[index] == '}':
            depth -= 1
            if depth == 0:
                return index
    raise AssertionError('Unclosed protocol source block')


def _function(tokens, name):
    prefix = ['func', name, '(', 't', '*', 'testing', '.', 'T', ')', '{']
    matches = _positions(tokens, prefix)
    assert len(matches) == 1, 'Missing or duplicate protocol root source'
    start = matches[0] + len(prefix) - 1
    return tokens[start + 1:_closing(tokens, start)]


def _literal_loop(tokens, variable, expected):
    prefix = ['for', '_', ',', variable, ':', '=', 'range', '[', ']', 'string', '{']
    matches = _positions(tokens, prefix)
    assert len(matches) == 1, 'Missing or duplicate literal protocol table'
    start = matches[0] + len(prefix) - 1
    end = _closing(tokens, start)
    values, index = [], start + 1
    while index < end:
        token = tokens[index]
        assert re.fullmatch(r'"[a-z0-9-]+"', token), 'Nonliteral protocol table value'
        values.append(token[1:-1])
        index += 1
        if index < end:
            assert tokens[index] == ',', 'Malformed literal protocol table'
            index += 1
    assert len(values) == len(set(values)) == len(expected) and set(values) == set(expected), 'Protocol source table drift'
    assert end + 1 < len(tokens) and tokens[end + 1] == '{', 'Missing protocol loop body'
    return end + 1, _closing(tokens, end + 1)


def source_bindings(source):
    tokens = _tokens(source)
    for root in (POSITIVE_ROOT, NEGATIVE_ROOT):
        body = _function(tokens, root)
        outer = _literal_loop(body, 'transport', POSITIVE_TRANSPORTS if root == POSITIVE_ROOT else XHTTP_TRANSPORTS)
        runs = _positions(body, ['t', '.', 'Run', '('])
        assert len(runs) == 1, 'Protocol subtests must have no intermediate groups'
        if root == POSITIVE_ROOT:
            bounds, arguments = outer, ['transport']
        else:
            bounds = _literal_loop(body, 'failure', FAILURES)
            assert outer[0] < bounds[0] < bounds[1] < outer[1], 'Protocol failure table must be transport-bound'
            arguments = ['transport', '+', '"/"', '+', 'failure']
        run = runs[0]
        assert bounds[0] < run < bounds[1], 'Protocol subtest escaped its literal table'
        call = ['t', '.', 'Run', '('] + arguments + [',', 'func', '(', 't', '*', 'testing', '.', 'T', ')', '{']
        assert body[run:run + len(call)] == call, 'Protocol subtest name binding drift'
    required = required_cases()
    assert len(required) == 30
    return required


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        assert key not in result, 'Duplicate native protocol event field'
        result[key] = value
    return result


def _invalid_constant(_value):
    raise AssertionError('Nonfinite native protocol JSON')


def verify(lines, source):
    required = source_bindings(source)
    states, completed, started, size = {}, False, False, 0
    for line in lines:
        assert isinstance(line, str), 'Invalid native protocol event input'
        size += len(line.encode('utf-8'))
        assert size <= MAX_BYTES and len(line) <= 1024 * 1024, 'Unbounded native protocol evidence'
        if not line.strip():
            continue
        try:
            row = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_invalid_constant)
        except (ValueError, TypeError) as error:
            raise AssertionError('Malformed native protocol event') from error
        assert isinstance(row, dict), 'Invalid native protocol event'
        action, package, imported, test = (row.get(key) for key in ('Action', 'Package', 'ImportPath', 'Test'))
        assert isinstance(action, str) and action, 'Invalid native protocol action'
        for key in ('Package', 'ImportPath', 'Test'):
            assert key not in row or isinstance(row[key], str) and row[key], 'Invalid native protocol metadata'
        assert package is not None or imported is not None, 'Missing native protocol package'
        target = test is not None and any(test == root or test.startswith(root + '/') for root in (POSITIVE_ROOT, NEGATIVE_ROOT))
        if target:
            assert test in required and package == BRIDGE and imported in (None, BRIDGE), 'Foreign or unbound protocol outcome'
        if package != BRIDGE and imported != BRIDGE:
            continue
        assert package in (None, BRIDGE) and imported in (None, BRIDGE), 'Ambiguous native protocol package'
        assert not completed, 'Native protocol event after package completion'
        assert action not in {'fail', 'skip', 'error', 'build-fail'} and row.get('Error') in (None, ''), 'Bridge regression failed or skipped'
        if action == 'build-output':
            assert test is None and not started and not states, 'Late or test-bound bridge build output'
            continue
        assert action in {'start', 'run', 'pause', 'cont', 'pass', 'output'}, 'Unknown bridge event action'
        if action == 'start':
            assert test is None and not started and not states, 'Duplicate or late bridge package start'
            started = True
            continue
        assert started, 'Bridge event before package start'
        if test is None:
            if action == 'pass':
                assert required <= states.keys() and all(value == 'passed' for value in states.values()), 'Incomplete bridge package'
                completed = True
            else:
                assert action == 'output', 'Invalid bridge package event order'
        elif action == 'run':
            assert test not in states and len(states) < 65536, 'Duplicate or unbounded bridge test'
            if target and test not in (POSITIVE_ROOT, NEGATIVE_ROOT):
                parent = test.split('/')[0]
                assert states.get(parent) == 'running', 'Protocol leaf before or after its parent'
            states[test] = 'running'
        elif action == 'pass':
            assert states.get(test) == 'running', 'Bridge pass without one start'
            if test in (POSITIVE_ROOT, NEGATIVE_ROOT):
                assert all(states.get(name) == 'passed' for name in required if name.startswith(test + '/')), 'Protocol parent passed before its leaves'
            states[test] = 'passed'
        elif action in {'pause', 'cont'}:
            assert states.get(test) == ('running' if action == 'pause' else 'paused'), 'Invalid bridge parallel event order'
            states[test] = 'paused' if action == 'pause' else 'running'
        else:
            assert action == 'output' and test in states, 'Bridge output without a test start'
    assert started and completed and required <= states.keys() and all(states[name] == 'passed' for name in required), 'Missing actual protocol outcomes or package completion'
    return len(required)


def main():
    assert len(sys.argv) == 2, 'Expected one actual native JSON stream'
    path = Path(sys.argv[1])
    assert path.is_file() and 0 < path.stat().st_size <= MAX_BYTES, 'Missing or unbounded native protocol evidence'
    source = Path(__file__).resolve().parent.parent / 'native/bridge/vless_ssh_wire_test.go'
    assert source.is_file() and 0 < source.stat().st_size <= 262144, 'Missing protocol source'
    with path.open(encoding='utf-8') as stream:
        count = verify(stream, source.read_text(encoding='utf-8'))
    print(f'Native protocol wire matrix: {count} actual ordered passes and one bridge completion')


if __name__ == '__main__':
    try:
        main()
    except (AssertionError, OSError, UnicodeError, ValueError):
        raise SystemExit('Native protocol evidence invalid')
