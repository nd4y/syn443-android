"""Finite, value-only observations for the disposable VPN process fixture.

This module performs no transport or device operations. Absence of an observation
is unknown, never a zero count, stopped owner or successful TUN witness.
"""
from collections import deque
from copy import deepcopy
import json
import re

MAX_COUNT = (1 << 31) - 1
MAX_REPORT_BYTES = 16_384
PHASES = frozenset((
    'Off', 'Online', 'Recovering', 'Connecting', 'NoNetwork', 'NeedsPermission',
    'NeedsAction', 'NeedsUnlock', 'BlockedByPolicy', 'Degraded',
))
REASONS = frozenset((
    'tcp_timeout', 'dns_timeout', 'tls_timeout', 'request_timeout',
    'response_timeout', 'network_timeout', 'network_unavailable',
    'dns_resolution_failed', 'tls_failed', 'transport_eof', 'transport_failed',
    'required_https_failed', 'required_https_ok', 'native_start',
    'native_start_failed', 'native_died', 'native_disconnected',
    'native_binding_died', 'native_bind_failed', 'native_late_start',
    'native_binding_timeout', 'native_progress_timeout', 'native_ipc_failed',
    'awaiting_identity_release', 'native_restart_budget', 'retry_scheduled',
    'user_stop', 'vpn_permission_required', 'explicit_resume_required',
    'network_changed', 'network_capabilities_changed',
))
COUNTERS = ('progress', 'accepted', 'active', 'handled', 'errors',
            'connectHeaders', 'requestHeaders', 'rejected')


def _count(value, maximum=MAX_COUNT):
    return value if type(value) is int and 0 <= value <= maximum else None


def _boolean(value):
    return value if type(value) is bool else None


def _valid_pid(value):
    return type(value) is str and re.fullmatch(r'[1-9][0-9]{0,9}', value) is not None


def controller_snapshot(value):
    result = {
        'available': type(value) is dict, 'phase': 'unknown', 'reason': 'unknown',
        'desiredOn': None, 'generation': None, 'resumeRequired': None,
        'attempt': None, 'heavyStarts': None, 'engineStateKnown': None,
        'engineActive': None, 'ready': None, 'ownedTun': None,
    }
    if type(value) is not dict:
        return result
    phase, reason = value.get('phase'), value.get('reason')
    result['phase'] = phase if type(phase) is str and phase in PHASES else 'unknown'
    result['reason'] = reason if type(reason) is str and reason in REASONS else 'unknown'
    for key in ('desiredOn', 'resumeRequired'):
        result[key] = _boolean(value.get(key))
    result['generation'] = _count(value.get('generation'))
    result['attempt'] = _count(value.get('attempt'), 30)
    history = value.get('heavyWallMs')
    if (type(history) is list and len(history) <= 3 and
            all(_count(item, 9_007_199_254_740_991) is not None for item in history)):
        result['heavyStarts'] = len(history)
    known, active = _boolean(value.get('engineStateKnown')), _boolean(value.get('engineActive'))
    result['engineStateKnown'] = known
    if known is True and active is not None:
        # LifecycleAccess publishes active=true only for the current READY
        # handshake. It publishes no owned-TUN observation; keep that unknown.
        result['engineActive'] = active
        result['ready'] = active
    return result


def native_snapshot(current, original):
    if type(current) is str and current == '':
        return {'known': True, 'present': False, 'relation': 'absent'}
    if not _valid_pid(current):
        return {'known': False, 'present': None, 'relation': 'unknown'}
    # pidof has no process-start-time witness. Report only the PID comparison,
    # never claim that a recycled number proves the original process survived.
    relation = ('same_pid' if current == original else 'different_pid') if _valid_pid(original) else 'unknown'
    return {'known': True, 'present': True, 'relation': relation}


def fixture_snapshot(value, expected_role):
    if expected_role not in ('ingress', 'egress'):
        raise ValueError('fixture_role')
    result = dict(role=expected_role, available=False, allowed=None, threadAlive=None)
    result.update({key: None for key in COUNTERS})
    if type(value) is not dict or value.get('role') != expected_role:
        return result
    counts = {key: _count(value.get(key)) for key in COUNTERS}
    if any(item is None for item in counts.values()):
        return result
    if (counts['active'] + counts['handled'] + counts['errors'] > counts['accepted'] or
            counts['connectHeaders'] > counts['accepted'] or
            counts['requestHeaders'] > counts['connectHeaders'] or
            counts['progress'] > counts['connectHeaders'] or
            counts['rejected'] > counts['accepted'] or
            (expected_role == 'egress' and counts['progress'] > counts['requestHeaders'])):
        return result
    result.update(counts)
    result.update(available=True, allowed=_boolean(value.get('allowed')),
                  threadAlive=_boolean(value.get('threadAlive')))
    return result


def reverse_snapshot(raw, port):
    """Observe only the owned mapping's presence, not reverse/TCP liveness."""
    unknown = {'known': False, 'ownedMappingPresent': None}
    if (type(raw) is not bytes or len(raw) > 16_384 or type(port) is not int or
            not 1 <= port <= 65_535):
        return unknown
    try:
        text = raw.decode('ascii', errors='strict')
    except UnicodeError:
        return unknown
    if any(ord(char) < 32 and char not in '\r\n\t' or ord(char) == 127 for char in text):
        return unknown
    lines = text.splitlines()
    if len(lines) > 64:
        return unknown
    owned, matches = 'tcp:' + str(port), 0
    for line in lines:
        if not line.strip():
            continue
        fields = line.split()
        if len(fields) != 3:
            return unknown
        if fields[1:] == [owned, owned]:
            matches += 1
    if matches > 1:
        return unknown
    return {'known': True, 'ownedMappingPresent': matches == 1}


class FailureEvidence:
    """At most eight changed polls; private PID operands never leave RAM."""
    def __init__(self, original_native):
        self._original_native = original_native if _valid_pid(original_native) else None
        self._transitions = deque(maxlen=8)
        self._last_sample_elapsed = None
        self.begin_poll()

    def begin_poll(self):
        self._controller = controller_snapshot(None)
        self._native = native_snapshot(None, self._original_native)

    def status(self, value):
        self._controller = controller_snapshot(value)

    def native(self, value):
        self._native = native_snapshot(value, self._original_native)

    def sample(self, elapsed_ms, ingress, egress):
        elapsed = _count(elapsed_ms)
        self._last_sample_elapsed = elapsed
        snapshot = {
            'controller': self._controller, 'native': self._native,
            'ingress': fixture_snapshot(ingress, 'ingress'),
            'egress': fixture_snapshot(egress, 'egress'),
        }
        if not self._transitions or self._transitions[-1]['observation'] != snapshot:
            self._transitions.append({'elapsedMs': elapsed, 'observation': deepcopy(snapshot)})

    def report(self, reverse=None):
        # Do not accept an arbitrary nested object into the diagnostic output.
        observed_reverse = {'known': False, 'ownedMappingPresent': None}
        if (type(reverse) is dict and reverse.get('known') is True and
                type(reverse.get('ownedMappingPresent')) is bool):
            observed_reverse = {'known': True, 'ownedMappingPresent': reverse['ownedMappingPresent']}
        # The status and pidof reads are independent observations, not an atomic
        # PID-to-READY binding, and there is no existing owned-TUN status field.
        result = {'version': 1, 'transitions': deepcopy(list(self._transitions)),
                  'lastSampleElapsedMs': self._last_sample_elapsed,
                  'reverse': observed_reverse, 'ownedTunAvailable': False,
                  'ownerBindingAvailable': False}
        if len(json.dumps(result, separators=(',', ':'), allow_nan=False).encode('utf-8')) > MAX_REPORT_BYTES:
            raise ValueError('evidence_bound')
        return result
