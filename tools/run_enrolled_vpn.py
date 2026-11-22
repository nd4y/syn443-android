"""Actual TLS/PKCE/DPoP -> controller -> signed policy -> isolated Go/TUN on a disposable emulator."""
import base64
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from enrollment_fixture import Fixture, decode
from run_vpn_process_faults import ROOT, PACKAGE, Proxy, Server, adb, call, pid, await_condition, vpn_stopped
from run_route_lifecycle import RouteProxy

def prepare_emulator_wifi():
    """Reassociate the disposable AVD if previous reboot cases left its Wi-Fi ineligible."""
    assert os.environ.get("GITHUB_ACTIONS") == "true" and os.environ.get("SYN443_CI_AVD") == "syn443-ci"
    assert adb("emu","avd","name").splitlines() == [b"syn443-ci",b"OK"]
    assert adb("shell","getprop","ro.hardware").strip() in (b"ranchu",b"goldfish")

    def observe():
        raw = adb("shell","am","instrument","-w","-e","observeFixtureWifi","true",
                  PACKAGE+".test/io.syn443.android.EnrollmentDriver",timeout=25)
        match = re.search(rb"INSTRUMENTATION_RESULT: wifiEligibility=(eligible|missing|unavailable|unvalidated|metered|unstable)\b", raw)
        assert match and b"INSTRUMENTATION_CODE: -1" in raw, "No app-UID Wi-Fi observation"
        return match[1].decode()

    status = observe()
    if status == "eligible":
        return
    print("Preparing disposable Wi-Fi after reboot; observed "+status,flush=True)
    adb("shell","svc","wifi","disable")
    time.sleep(2)
    adb("shell","svc","wifi","enable")
    # The virtual access point is open. Only select its emulator-provided name
    # if the Android Wi-Fi service itself lists it. Never adopt an arbitrary SSID.
    sdk = int(adb("shell","getprop","ro.build.version.sdk").strip())
    if sdk >= 30:
        adb("shell","cmd","wifi","start-scan")
        time.sleep(3)
        scan = adb("shell","cmd","wifi","list-scan-results").decode(errors="replace")
        if re.search(r"\bAndroidWifi\b", scan):
            adb("shell","cmd","wifi","connect-network","AndroidWifi","open")
    end = time.monotonic()+50
    observations = []
    while True:
        status = observe()
        if status == "eligible":
            print("App UID confirmed validated unmetered Wi-Fi after reassociation",flush=True)
            return
        if not observations or observations[-1] != status:
            observations.append(status)
        if time.monotonic() >= end:
            raise AssertionError("Disposable Wi-Fi eligibility after reassociation: "+",".join(observations))
        time.sleep(2)


def stopped_rollback_recovered(controller,generation):
    # A provider read is the explicit recreation request. An empty PID must
    # never short-circuit that read when no foreground UI is polling for us.
    state=call('status')
    assert not state['desiredOn'] and state['generation']==generation
    assert not pid(':engine'),'Stop allowed an unexpected replacement native owner'
    return (pid(':controller') not in ('',controller) and state.get('engineActive') is False and
        state['policy']['phase']=='rolled_back' and state['policy'].get('activeRevision')==1 and
        not call('auth-status')['busy'])

def exchange_through_proxy(proxy):
    # Keep the client half-open while the application UID reads the reply.
    # A pipe directly into toybox nc can close its input before the peer responds.
    proxy.payload_received = threading.Event()
    try:
        command = (r"(printf 'GET /syn443-payload HTTP/1.1\r\nHost: fixture.invalid\r\n"
                   r"Connection: close\r\n\r\n'; sleep 3) | run-as " + PACKAGE +
                   " toybox nc -w 5 203.0.113.10 80")
        response = adb('shell', '-T', command, timeout=12)
        confirmed = proxy.payload_received.wait(1)
        status = re.match(rb'HTTP/1\.1 ([0-9]{3}) ', response)
        if not confirmed or status is None or status[1] != b'204':
            raise AssertionError('Application payload: expected proxy received=%s, HTTP status=%s' %
                                 (confirmed, status[1].decode() if status else 'absent'))
    finally:
        proxy.payload_received = None


def logout(fresh_install=False):
    if fresh_install:
        # Package installation can return before its provider can answer. Only poll a read.
        await_condition(lambda: bool(call('auth-status').get('phase')), 40)
    call('auth-cancel')

    def signed_out():
        if not vpn_stopped():
            return False
        snapshot = call('auth-status')
        return snapshot.get('phase') == 'SIGNED_OUT' and snapshot.get('busy') is False

    await_condition(signed_out, 40)


def upgrade_directory(system_installer=False, historical=False):
    if historical:
        return Path(os.environ['RUNNER_TEMP']) / 'historical-upgrade'
    return Path(os.environ['RUNNER_TEMP']) / ('syn443-installer-private' if system_installer else 'upgrade-fixture')


def check_enrolled_upgrade(fixture, proxy, auth_generation, system_installer=False, historical=False):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('SYN443_CI_AVD') != 'syn443-ci'
            or adb('emu', 'avd', 'name').splitlines() != [b'syn443-ci', b'OK']):
        raise ValueError('This APK upgrade requires the disposable CI emulator')
    directory = upgrade_directory(system_installer, historical)
    receipt = json.loads((directory / 'upgrade.json').read_bytes())

    def installed_version():
        versions = re.findall(rb'^\s*versionCode=(\d+)\b', adb('shell', 'dumpsys', 'package', PACKAGE), re.MULTILINE)
        if len(versions) != 1:
            raise ValueError('Installed package version is ambiguous')
        return int(versions[0])

    def binding():
        return {(thumb, session['deviceId']) for thumb, session in fixture.sessions.copy().items()}

    original = binding()
    assert len(original) == 1 and fixture.registrations == 1
    assert installed_version() == receipt['previous']
    assert call('status')['policy']['activeRevision'] == 1
    if historical:
        exchange_through_proxy(proxy)
    call('disconnect')
    await_condition(vpn_stopped)
    before = call('status')
    assert before['desiredOn'] is False
    if system_installer:
        from installer_cancel_ui import cancel_installer
        cancel_installer(directory, next(iter(original))[1], installed_version, receipt['previous'])
        assert call('auth-status')['generation'] == auth_generation and binding() == original and fixture.registrations == 1
        assert vpn_stopped() and call('status')['generation'] == before['generation']
        assert call('status')['policy']['activeRevision'] == 1
    response = adb('install', '-r', str(directory / 'new-debug.apk'), timeout=120)
    assert b'Success' in response.splitlines() and installed_version() == receipt['following'] > receipt['previous']
    adb('shell', 'am', 'start', '-W', '-n', PACKAGE + '/.MainActivity')
    def restored_off():
        state = call('status')
        assert state['desiredOn'] is False and state['generation'] == before['generation'] and vpn_stopped()
        return state['policy'].get('activeRevision') == 1 and not call('auth-status')['busy']
    await_condition(restored_off)
    assert call('auth-status')['generation'] == auth_generation
    # The fixture counts policy requests only after verifying the signed DPoP proof, nonce and access token.
    requests = fixture.policy_requests
    fixture.revision = 2
    await_condition(lambda: call('policy-refresh').get('admitted') is True, 30)
    await_condition(lambda: fixture.policy_requests > requests and call('status')['policy'].get('desiredRevision') == 2)
    assert call('status')['desiredOn'] is False and vpn_stopped()
    progress = proxy.progress
    call('connect')
    await_condition(lambda: call('status')['phase'] == 'Online' and
                    call('status')['policy'].get('activeRevision') == 2 and
                    call('status')['policy'].get('phase') == 'committed' and proxy.progress > progress)
    assert binding() == original and fixture.registrations == 1
    assert call('status')['policy']['activeRevision'] == 2 and call('auth-status')['generation'] == auth_generation
    if historical:
        exchange_through_proxy(proxy)


def committed_online(status, revision):
    policy = status.get('policy')
    return (status.get('phase') == 'Online' and status.get('engineActive') is True and
            isinstance(policy, dict) and policy.get('activeRevision') == revision and
            policy.get('phase') == 'committed')


def signed_program_failover(fixture, primary, generation):
    reserve = Server(('127.0.0.1', 0), RouteProxy)
    reserve.ssh_ok, reserve.health_ok, reserve.delay, reserve.route_probes = True, True, 0, 0
    port = reserve.server_address[1]
    threading.Thread(target=reserve.serve_forever, daemon=True).start()
    try:
        adb('reverse', 'tcp:'+str(port), 'tcp:'+str(port))
        route = copy.deepcopy(fixture.config)
        preferred = route['outbounds'][0]['tag']
        members = [preferred, 'reserve']
        route['outbounds'] += [dict(route['outbounds'][0], tag='reserve', server_port=port),
            {'type':'selector', 'tag':'internal', 'outbounds':members, 'interrupt_exist_connections':False}]
        route['route']['rules'] = [{'ip_cidr':['192.0.2.9/32','203.0.113.10/32'], 'action':'route', 'outbound':'internal'}]
        route['route_checks'] = [{'outbound':tag,'required':tag=='internal',
            'checks':[{'method':'ssh_banner','target':'192.0.2.9:22'}]} for tag in ['internal',*members]]
        route['route_failover'] = {'selector':'internal','network_mode':'wifi','intent':'INTERNAL','members':members}
        fixture.extra_capabilities = ('route.health.v1','route.failover.v1')
        fixture.decision_program = {'revision':7,'confirmations':4,'minSwitchIntervalMs':120000}
        fixture.config = route
        fixture.revision = 2
        call('policy-refresh')
        def active():
            return committed_online(call('status'), 2)
        def measured(member):
            rows = call('routes-status')['routes']
            by_tag = {row['label']:row for row in rows}
            if member not in by_tag or 'internal' not in by_tag:
                return False
            group = by_tag['internal']
            return group.get('state') == 'working' and group.get('measuredPath') == [group['id'], by_tag[member]['id']]
        await_condition(lambda: active() and measured(preferred), 100)
        exchange_through_proxy(primary)
        original = pid(':engine')
        activation = call('status')['policy']['activationGeneration']
        assert original and fixture.registrations==1
        thumb, = fixture.sessions
        original_device = fixture.sessions[thumb]['deviceId']
        before = reserve.route_probes
        primary.ssh_ok = False
        # No check or switch command is issued after the outage.
        await_condition(lambda: measured('reserve'), 240)
        assert reserve.route_probes >= before+4, 'Reserve lacked a successful comparator for four batches'
        exchange_through_proxy(reserve)
        assert active() and pid(':engine')==original and call('status')['policy']['activationGeneration']==activation
        assert call('auth-status')['generation']==generation and fixture.registrations==1 and fixture.sessions[thumb]['deviceId']==original_device
    finally:
        primary.ssh_ok = True
        try:
            adb('reverse','--remove','tcp:'+str(port))
        finally:
            reserve.shutdown()
            reserve.server_close()


def enrolled_management_outage(fixture, proxy, generation):
    from process_failure_evidence import reverse_snapshot

    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('SYN443_CI_AVD') != 'syn443-ci'
            or adb('emu', 'avd', 'name').splitlines() != [b'syn443-ci', b'OK']):
        raise ValueError('Disposable Wi-Fi emulator required')
    port = fixture.server.server_port
    assert port != proxy.server_address[1] and fixture.telemetry_enabled
    assert fixture.issuer.startswith(fixture.origin + '/') and fixture.origin == 'https://127.0.0.1:' + str(port)
    binding = set((key, row['deviceId']) for key, row in fixture.sessions.copy().items())
    assert len(binding) == 1 and fixture.registrations == 1
    endpoint = 'tcp:' + str(port)

    def confirm_mapping(present):
        assert reverse_snapshot(adb('reverse', '--list'), port) == {'known': True, 'ownedMappingPresent': present}

    def offline():
        confirm_mapping(False)
        result = subprocess.run(['adb', '-e', 'shell', '-T', 'run-as', PACKAGE, 'toybox', 'nc',
                                 '-w', '2', '127.0.0.1', str(port)], stdin=subprocess.DEVNULL,
                                capture_output=True, timeout=8)
        assert result.returncode != 0 and b'connection refused' in (result.stdout + result.stderr).lower()

    def bound():
        return (fixture.registrations == 1 and
                {(key, row['deviceId']) for key, row in fixture.sessions.copy().items()} == binding and
                call('auth-status')['generation'] == generation)

    confirm_mapping(True)
    exchange_through_proxy(proxy)
    original_controller, original_engine = pid(':controller'), pid(':engine')
    assert original_controller and original_engine and committed_online(call('status'), 1)
    adb('reverse', '--remove', endpoint)
    try:
        offline()
        call('policy-refresh')
        exchange_through_proxy(proxy)
        call('fault-controller')

        def replaced():
            if not committed_online(call('status'), 1):
                return False
            controller, engine = pid(':controller'), pid(':engine')
            return controller not in ('', original_controller) and engine not in ('', original_engine)

        await_condition(replaced, 100)
        assert bound()
        offline()
        exchange_through_proxy(proxy)
    finally:
        adb('reverse', endpoint, endpoint)

    confirm_mapping(True)
    requests = fixture.policy_requests
    fixture.revision = 2
    last_refresh = None

    def renewed():
        nonlocal last_refresh
        if fixture.policy_requests > requests and committed_online(call('status'), 2):
            return True
        now = time.monotonic()
        if last_refresh is None or now - last_refresh >= 7:
            call('policy-refresh')
            last_refresh = now
        return False

    await_condition(renewed, 90)
    assert bound()
    exchange_through_proxy(proxy)


def enrolled_operator_mode(fixture, primary):
    from policy_fixture import b64
    if os.environ.get('GITHUB_ACTIONS') != 'true' or adb('emu', 'avd', 'name').splitlines() != [b'syn443-ci', b'OK']:
        raise ValueError('Disposable Wi-Fi emulator required')
    serial = adb('get-serialno').decode().strip()
    if not re.fullmatch(r'emulator-[0-9]+', serial):
        raise ValueError('Unexpected emulator identity')

    def cli(operation, *options):
        raw = subprocess.check_output([sys.executable, str(ROOT / 'tools/syn443ctl.py'), '--serial', serial,
                                       operation, *options], timeout=20)
        result = json.loads(raw)
        assert result['schemaVersion'] == 1 and result['operation'] == operation
        return result['result']

    reserve = Server(('127.0.0.1', 0), RouteProxy)
    reserve.ssh_ok, reserve.health_ok, reserve.delay, reserve.route_probes = True, True, 0, 0
    port = reserve.server_address[1]
    threading.Thread(target=reserve.serve_forever, daemon=True).start()
    try:
        adb('reverse', 'tcp:' + str(port), 'tcp:' + str(port))
        route = copy.deepcopy(fixture.config)
        base = route['outbounds'][0]
        names = ['hop-%02d' % i for i in range(21)]
        features = ['TCP', 'IPV4']
        graph = {'schemaVersion': 1, 'edges': [], 'hops': [], 'templates': [{'id': 'one', 'slots': [names]}],
                 'groups': [{'id': 'office', 'intent': 'INTERNAL', 'features': features, 'templates': ['one']}]}
        catalogue = {}
        for name in names:
            eligible = name == names[-1]
            graph['hops'].append({'id': name, 'entryModes': ['WIFI' if eligible else 'HOME_WIFI'],
                                  'exitClass': 'INTERNAL', 'features': features})
            catalogue[name] = dict(base, tag=name, server_port=port if eligible else primary.server_address[1])
        def encode(document):
            return b64(json.dumps(document, sort_keys=True, separators=(',', ':')).encode())
        route['adaptive_routes'] = {'schemaVersion': 1, 'graphB64': encode(graph),
                                    'catalogueB64': encode(catalogue), 'groups': {'office': 'managed-office'}}
        route['outbounds'].append({'type': 'syn443-adaptive', 'tag': 'managed-office', 'group': 'office'})
        route['route']['rules'] = [
            {'ip_cidr': ['203.0.113.10/32'], 'network': ['tcp'], 'action': 'route', 'outbound': 'managed-office'},
            {'network': ['udp'], 'action': 'reject', 'method': 'drop'},
        ]
        route['route_checks'] = [{'outbound': 'managed-office', 'required': True,
                                  'checks': [{'method': 'ssh_banner', 'target': '192.0.2.9:22'}]}]
        route['network_mode'] = {'preferredMode': 'AUTO', 'userModes': ['WIFI'], 'maxOverrideMinutes': 3}
        fixture.extra_capabilities = ('route.health.v1', 'route.adaptive-tcp.v1', 'route.decision.v1', 'network.mode-selection.v1')
        fixture.config = route
        fixture.revision = 2
        call('policy-refresh')

        def working():
            if not committed_online(call('status'), 2):
                return False
            return any(row.get('state') == 'working' and row.get('measuredPath') == [names[-1]]
                       for row in call('routes-status')['routes'])

        def mode(source):
            result = cli('mode-get')
            return result if (result.get('state') == 'observed' and result.get('effective') == 'WIFI'
                              and result.get('source') == source and result.get('allowed') == ['WIFI']) else None

        await_condition(working, 120)
        exchange_through_proxy(reserve)
        automatic = mode('automatic')
        assert automatic and automatic['maxMinutes'] == 3
        submitted = cli('mode-set', '--stamp', automatic['stamp'], '--mode', 'WIFI', '--minutes', '2')
        assert submitted == {'admitted': True, 'generation': automatic['generation'], 'networkEpoch': automatic['networkEpoch']}
        await_condition(lambda: mode('manual') and working(), 100)
        exchange_through_proxy(reserve)
        manual = mode('manual')
        assert manual and manual['stamp'] != automatic['stamp'] and 0 < manual['remainingMs'] <= 120_000
        cleared = cli('mode-set', '--stamp', manual['stamp'], '--mode', 'AUTO', '--minutes', '0')
        assert cleared == submitted
        await_condition(lambda: mode('automatic') and working(), 100)
        exchange_through_proxy(reserve)
        assert fixture.registrations == 1
    finally:
        try:
            adb('reverse', '--remove', 'tcp:' + str(port))
        finally:
            reserve.shutdown()
            reserve.server_close()


def check_rejected_policies(fixture, proxy, generation):
    """Deliver each negative AC06 example over the normal, authenticated policy endpoint."""
    from policy_fixture import b64

    def committed(revision):
        return committed_online(call('status'), revision)

    def refresh_until(observed):
        # Foreground reconciliation admits forced requests at a bounded rate.
        last_request = None
        def ready():
            nonlocal last_request
            if observed():
                return True
            now = time.monotonic()
            if last_request is None or now - last_request >= 7:
                call('policy-refresh')
                last_request = now
            return False
        await_condition(ready, 75)

    thumb, = fixture.sessions
    device = fixture.sessions[thumb]['deviceId']
    first = fixture.envelopes[(thumb, 1)]
    fixture.revision = 2
    refresh_until(lambda: committed(2))
    engine = pid(':engine')
    activation = call('status')['policy']['activationGeneration']
    assert engine

    next_policy = fixture.publisher.sign(fixture.config, revision=3, key_thumbprint=thumb)
    header_text, payload_text, signature = next_policy.split('.')
    header = json.loads(decode(header_text))
    payload = json.loads(decode(payload_text))
    damaged = bytearray(decode(signature))
    damaged[0] ^= 1
    invalid_signature = '.'.join([header_text, payload_text, b64(damaged)])
    other_device = dict(payload, targetDevice='different-synthetic-recipient')
    unsupported = dict(payload, requiredCapabilities=payload['requiredCapabilities'] + ['future.fixture.v1'])
    examples = [invalid_signature, fixture.publisher.signed_document(header, other_device),
                first, fixture.publisher.signed_document(header, unsupported)]

    # A valid outer signature cannot retarget the separately signed decision program.
    comparison = dict(fixture.config, route_failover={})
    with_program = fixture.publisher.sign(comparison, revision=3, key_thumbprint=thumb,
        extra_capabilities=('route.health.v1', 'route.failover.v1'),
        decision_program={'revision': 7, 'confirmations': 4, 'minSwitchIntervalMs': 120000})
    nested_policy = json.loads(decode(with_program.split('.')[1]))
    inner_header, inner_body, _ = nested_policy['decisionBundle'].split('.')
    foreign = dict(json.loads(decode(inner_body)), targetDevice='different-synthetic-recipient')
    nested_policy['decisionBundle'] = fixture.publisher.signed_document(json.loads(decode(inner_header)), foreign)
    examples.append(fixture.publisher.signed_document(header, nested_policy))

    # The current policy remains valid for the whole exercise. Each example is
    # served to this session, and a new successful proxy exchange must follow it.
    fixture.policy_example = examples[0]
    fixture.revision = 3
    for example in examples:
        deliveries = fixture.example_deliveries.get(example, 0)
        fixture.policy_example = example
        refresh_until(lambda: fixture.example_deliveries.get(example, 0) > deliveries and not call('auth-status')['busy'])
        assert committed(2)
        received_before = proxy.progress
        await_condition(lambda: proxy.progress > received_before, 100)
        assert committed(2) and pid(':engine') == engine
        assert call('status')['policy']['activationGeneration'] == activation
        assert fixture.registrations == 1 and set(fixture.sessions) == {thumb}
        assert fixture.sessions[thumb]['deviceId'] == device and call('auth-status')['generation'] == generation
        assert (thumb, 3) not in fixture.activation_reports

    fixture.policy_example = None
    refresh_until(lambda: committed(3))
    assert fixture.registrations == 1 and fixture.sessions[thumb]['deviceId'] == device
    assert call('auth-status')['generation'] == generation


def failure_summary():
    state=call('status');auth=call('auth-status');policy=state.get('policy',{})
    phases={'unmanaged','unavailable','blocked','prepared','applying','committed','degraded','rolled_back','rejected','released'}
    safe_policy={'phase':policy.get('phase') if policy.get('phase') in phases else 'unknown'}
    for name in ('activeRevision','lastKnownGoodRevision','candidateRevision','activationGeneration','maxRevision'):
        value=policy.get(name)
        if type(value) is int and 0<=value<=9007199254740991:safe_policy[name]=value
    def observed_bool(key):
        value=state.get(key)
        return value if type(value) is bool else None
    return {'desiredOn':observed_bool('desiredOn'),'engineActive':observed_bool('engineActive'),
        'engineStateKnown':observed_bool('engineStateKnown'),'offPhase':state.get('phase')=='Off',
        'intentGeneration':state.get('generation') if type(state.get('generation')) is int else None,
        'policy':safe_policy,'authBusy':auth.get('busy') is True,
        'telemetryAvailable':auth.get('telemetryAvailable') is True,'telemetryConsent':auth.get('telemetryEnabled') is True,
        'controllerPresent':bool(pid(':controller')),'nativePresent':bool(pid(':engine'))}

def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish'),'Emulator only'
    assert PACKAGE+'.test/io.syn443.android.EnrollmentDriver' in adb('shell','pm','list','instrumentation').decode(),'Test APK enrollment driver is not installed'
    suite=ET.Element('testsuite',name='SYN443 enrolled native VPN')
    args=sys.argv[1:]
    if args not in ([], ['--system-installer'], ['--historical']):
        raise ValueError('Unexpected enrollment scenario')
    installer_only=args==['--system-installer']
    historical=args==['--historical']
    out=(Path(os.environ['RUNNER_TEMP'])/'syn443-installer-private'/'result.xml' if installer_only
         else ROOT/'app/build/outputs/androidTest-results/external/TEST-enrolled-vpn.xml')
    if historical:
        out=upgrade_directory(historical=True)/'result.xml'
    proxy=Server(('127.0.0.1',0),RouteProxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    proxy.ssh_ok=True;proxy.delay=0;proxy.health_ok=True;proxy.route_probes=0
    port=proxy.server_address[1];adb('reverse','tcp:'+str(port),'tcp:'+str(port))
    config={'outbounds':[{'type':'http','tag':'enrolled-proxy','server':'127.0.0.1','server_port':port}], 'route':{'final':'enrolled-proxy'}}
    fixture=None
    def close_fixture():
        nonlocal fixture
        if fixture:
            adb('reverse','--remove','tcp:'+str(fixture.server.server_port));fixture.close();fixture=None
    def setup(pending=False, telemetry=None, installer=False):
        nonlocal fixture
        device=None
        if installer:
            if os.environ.get('GITHUB_ACTIONS')!='true' or adb('emu','avd','name').splitlines()!=[b'syn443-ci', b'OK']:
                raise ValueError('Disposable installer emulator required')
            from enrollment_fixture import decode
            directory=upgrade_directory(True)
            envelope=(directory/'syn443-update.txt').read_text(encoding='ascii')
            device=json.loads(decode(envelope.split('.')[1]))['scope']['deviceId']
            assert b'Success' in adb('install','-r',str(directory/'installer-base.apk'),timeout=120).splitlines()
        logout(fresh_install=historical or installer)
        close_fixture();call('policy-test-reset');call('test-reset')
        if telemetry:
            prepare_emulator_wifi()
        call('import',base64.b64encode(json.dumps(config,separators=(',',':')).encode()).decode())
        call('test-health','synthetic-http');proxy.allowed=True
        # Keep the assignment valid for the first periodic job while the access token rotates.
        fixture=Fixture(config,assigned_device=device,policy_ttl_seconds=3600 if telemetry=='stopped' else 600)
        fixture_port=fixture.server.server_port
        fixture.telemetry_enabled=telemetry is not None
        fixture.pending_policy_requests=1 if pending else 0
        adb('reverse','tcp:'+str(fixture_port),'tcp:'+str(fixture_port))
        data=json.dumps(fixture.bootstrap(),separators=(',',':')).encode()
        subprocess.run(['adb','-e','shell','-T','run-as',PACKAGE,'dd','of=no_backup/operator-identity.json'],input=data,capture_output=True,check=True,timeout=15)
        call('auth-bootstrap-file');await_condition(lambda:call('auth-status').get('configured') and not call('auth-status').get('busy'),20)
        before=proxy.progress
        driver=subprocess.run(['adb','-e','shell','am','instrument','-w','-e','fixturePort',str(fixture_port),'-e','fixtureCa',fixture.ca,
            *(['-e','fixtureTelemetry','stopped' if telemetry=='stopped' else 'true'] if telemetry else []),
            PACKAGE+'.test/io.syn443.android.EnrollmentDriver'],capture_output=True,timeout=(150 if telemetry=='stopped' else 75) + (60 if telemetry else 0))
        result=driver.stdout.decode()
        if driver.returncode or 'synthetic_enrollment_verified' not in result or 'INSTRUMENTATION_CODE: -1' not in result:
            stage=re.search(r'INSTRUMENTATION_RESULT: stage=([a-z_]{1,40})',result)
            state=call('auth-status');safe={k:v for k,v in state.items() if k in ('phase','reason') and isinstance(v,str) and re.fullmatch('[A-Z_]{0,64}',v)}
            raise AssertionError('Synthetic enrollment failed at '+(stage[1] if stage else 'driver_launch')+' '+json.dumps(safe))
        assert fixture.registrations==1 and not call('status')['desiredOn']
        if telemetry=='stopped':
            assert proxy.progress>before
            await_condition(vpn_stopped)
            return result
        adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        before=proxy.progress;call('connect')
        await_condition(lambda:call('status').get('phase')=='Online' and call('status').get('policy',{}).get('phase')=='committed' and proxy.progress>before)
        return result
    names=['enrolledPendingAssignmentRetriesWhileVisible','enrolledSignedAssignmentStartsRealTun','enrolledControllerDeathRecoversAuthorizedCache',
           'enrolledCandidateRegressionRollsBack','enrolledRevocationStopsNativeWithoutLocalFallback',
           'enrolledLogoutRetiresFrozenNativeBeforeAcknowledging',
           'enrolledAssignedRoutesCommitWithOptionalFailure',
           'enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet',
           'enrolledStopFencesPendingCandidateRouteSuccess','enrolledStoppedTelemetryUsesScheduledWorkWithoutRevivingVpn',
           'enrolledRejectedUpdatesRetainAuthorizedTunnel', 'enrolledNegotiatedFailoverAutonomouslySwitchesWorkingTun',
           'enrolledOperatorModeKeepsTrafficOnTheObservedWiFiPath', 'enrolledManagementOutageRetainsTunnelThroughControllerDeath',
           'enrolledVersionUpgradeRetainsBindingPolicyAndRealTun']
    if installer_only:
        names=['enrolledSystemInstallerCancelKeepsBoundPolicy']
    elif historical:
        names=['enrolledHistoricalUpgradeKeepsOriginalBindingAndPayload']
    def observed_report(revision,outcome,selected):
        return any(r['policyRevision']==revision and r['outcome']==outcome and r['activePolicyRevision']==selected
                   for r in list(fixture.activation_reports.values()))
    try:
        for name in names:
            case=ET.SubElement(suite,'testcase',classname='io.syn443.android.EnrolledVpn',name=name)
            try:
                telemetry_modes={'enrolledManagementOutageRetainsTunnelThroughControllerDeath':'foreground',
                                 'enrolledCandidateRegressionRollsBack':'foreground',
                                 'enrolledStoppedTelemetryUsesScheduledWorkWithoutRevivingVpn':'stopped'}
                driver_result=setup(name=='enrolledPendingAssignmentRetriesWhileVisible',telemetry=telemetry_modes.get(name), installer=installer_only)
                before=proxy.progress;generation=call('auth-status')['generation']
                if name=='enrolledPendingAssignmentRetriesWhileVisible':
                    assert fixture.policy_requests>=2 and fixture.registrations==1
                    assert call('status')['policy']['activeRevision']==1
                elif name=='enrolledSignedAssignmentStartsRealTun':
                    assert call('status')['policy']['activeRevision']==1 and fixture.policy_requests>=1
                    await_condition(lambda:observed_report(1,'committed',1),45)
                    call('disconnect');await_condition(vpn_stopped)
                    try:call('import',base64.b64encode(json.dumps(config).encode()).decode());raise RuntimeError('managed import unexpectedly accepted')
                    except AssertionError:pass
                    before=proxy.progress;call('connect')
                    await_condition(lambda:call('status').get('phase')=='Online' and proxy.progress>before)
                elif name=='enrolledManagementOutageRetainsTunnelThroughControllerDeath':
                    enrolled_management_outage(fixture, proxy, generation)
                elif name=='enrolledControllerDeathRecoversAuthorizedCache':
                    old_controller=pid(':controller');old_engine=pid(':engine');assert old_controller and old_engine
                    fixture.policy_status=503;call('fault-controller')
                    await_condition(lambda:bool(pid(':controller')) and pid(':controller')!=old_controller and bool(pid(':engine')) and pid(':engine')!=old_engine)
                    before=proxy.progress
                    await_condition(lambda:call('auth-status').get('generation')==generation and call('status').get('phase')=='Online' and proxy.progress>before)
                    assert fixture.registrations==1
                elif name=='enrolledNegotiatedFailoverAutonomouslySwitchesWorkingTun':
                    signed_program_failover(fixture, proxy, generation)
                elif name=='enrolledOperatorModeKeepsTrafficOnTheObservedWiFiPath':
                    enrolled_operator_mode(fixture, proxy)
                elif name=='enrolledRejectedUpdatesRetainAuthorizedTunnel':
                    check_rejected_policies(fixture, proxy, generation)
                elif name=='enrolledCandidateRegressionRollsBack':
                    try:
                        await_condition(lambda:bool(fixture.telemetry_receipts),330)
                    except Exception:
                        # Synthetic-only flags and counters; no network, identity or event data.
                        print('First telemetry receipt observation:', {
                            'eligibleWifiAtConsent':'telemetry_wifi_eligible=true' in driver_result,
                            'httpRequests':fixture.telemetry_requests,'acknowledged':len(fixture.telemetry_receipts)},flush=True)
                        raise
                    first_received=fixture.telemetry_receipts[0][0]
                    assert all(('policy','rolled_back') not in events for _,events in fixture.telemetry_receipts)
                    broken=copy.deepcopy(config);broken['outbounds'][0]['server_port']=1;fixture.config=broken;fixture.revision=2
                    call('policy-refresh')
                    await_condition(lambda:call('status').get('policy',{}).get('phase')=='rolled_back' and call('status').get('phase')=='Online' and proxy.progress>before)
                    assert call('status')['policy']['activeRevision']==1
                    await_condition(lambda:observed_report(2,'rolled_back',1),45)
                    await_condition(lambda:any(('policy','rolled_back') in events for _,events in fixture.telemetry_receipts),180)
                    received=next(at for at,events in fixture.telemetry_receipts if ('policy','rolled_back') in events)
                    assert 0<received-first_received<300, 'critical rollback missed the regular upload interval'
                    assert fixture.registrations==1 and call('auth-status')['generation']==generation
                    assert call('status')['phase']=='Online' and proxy.progress>before
                elif name in ('enrolledAssignedRoutesCommitWithOptionalFailure','enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet','enrolledStopFencesPendingCandidateRouteSuccess'):
                    changed=copy.deepcopy(config)
                    changed['outbounds'].append({'type':'http','tag':'unavailable-route','server':'127.0.0.1','server_port':1})
                    changed['route_checks']=[{'outbound':'enrolled-proxy','required':True,'checks':[{'method':'ssh_banner','target':'192.0.2.9:22'}]},
                        {'outbound':'unavailable-route','required':False,'checks':[{'method':'tcp','target':'192.0.2.9:22'}]}]
                    original=pid(':engine');probes=proxy.route_probes
                    if name=='enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet':
                        changed['route_checks'][1]['required']=True;fixture.allow_degraded=True
                    if name=='enrolledStopFencesPendingCandidateRouteSuccess':proxy.delay=4
                    fixture.config=changed;fixture.revision=2;call('policy-refresh')
                    if name=='enrolledAssignedRoutesCommitWithOptionalFailure':
                        await_condition(lambda:call('status').get('policy',{}).get('activeRevision')==2 and call('status')['policy']['phase']=='committed' and call('status')['phase']=='Online',90)
                        rows=call('routes-status')['routes']
                        assert rows[0]['state']=='working' and rows[1]['state']=='failed' and proxy.route_probes>probes
                        assert pid(':engine')!=original and proxy.progress>before
                    elif name=='enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet':
                        await_condition(lambda:call('status')['policy']['phase']=='rolled_back' and call('status')['phase']=='Online',90)
                        assert call('status')['policy']['activeRevision']==1 and call('status')['policy']['reason']=='required_route_failed'
                        assert proxy.progress>before
                    else:
                        await_condition(lambda:call('status')['policy']['phase']=='applying' and proxy.route_probes>probes,60)
                        call('disconnect');await_condition(vpn_stopped);generation_after=call('status')['generation'];time.sleep(5)
                        state=call('status')
                        assert not state['desiredOn'] and state['generation']==generation_after and vpn_stopped()
                        # A trial permit authorizes only the candidate; the previous active
                        # envelope is intentionally not reported as a usable current permit.
                        assert state['policy']['phase'] in ('applying','rolled_back')
                        assert state['policy'].get('activeRevision') in (None,1)
                        # Prove the durable pointer survived, rather than mistaking an
                        # unavailable runtime-view field for a committed revision.
                        fixture.policy_status=503;controller=pid(':controller');call('fault-controller')
                        await_condition(lambda:stopped_rollback_recovered(controller,generation_after),45)
                        assert call('status')['generation']==generation_after and not call('status')['desiredOn'] and vpn_stopped()
                    proxy.delay=0
                elif name=='enrolledStoppedTelemetryUsesScheduledWorkWithoutRevivingVpn':
                    job=re.search(r'(?m)^INSTRUMENTATION_RESULT: job=([0-9]{1,10})\s*$',driver_result)
                    namespace=re.search(r'(?m)^INSTRUMENTATION_RESULT: namespace=([A-Za-z0-9_.-]{0,80})\r?$',driver_result)
                    until_eligible=re.search(r'(?m)^INSTRUMENTATION_RESULT: untilEligibleMs=([0-9]{1,6})\s*$',driver_result)
                    assert job and namespace and until_eligible and 0<int(until_eligible[1])<=900_000
                    remaining_ms=int(until_eligible[1])
                    due=time.monotonic()+remaining_ms/1000
                    deadline_ms=int(time.time()*1000)+remaining_ms
                    signed_policy,=fixture.envelopes.values()
                    policy=json.loads(decode(signed_policy.split('.')[1]))
                    session,=fixture.sessions.values()
                    assert session['accessUntilMs'] < deadline_ms
                    assert policy['offlineUntilMs'] > deadline_ms+120_000, 'assignment expires before worker acceptance'
                    await_condition(vpn_stopped)
                    stopped=call('status')['generation']
                    assert not fixture.telemetry_receipts
                    adb('shell','input','keyevent','KEYCODE_HOME')
                    old=pid(':controller');assert old
                    call('fault-controller')
                    await_condition(lambda:pid(':controller')!=old,30)
                    cmd=['shell','cmd','jobscheduler','run','-f','-u','0']
                    if namespace[1]:cmd+=['-n',namespace[1]]
                    # JobScheduler can launch a service early, but WorkManager independently
                    # checks the first eligible wall-clock time for periodic work. Preserve the
                    # entire production interval, including session token refresh while stopped.
                    def received_off():
                        return any(('vpn','off') in events for _,events in fixture.telemetry_receipts)
                    print('Waiting for the first eligible periodic telemetry upload',flush=True)
                    while not received_off() and time.monotonic()<due:
                        time.sleep(min(5,max(0,due-time.monotonic())))
                    if not received_off():
                        adb(*cmd,PACKAGE,job[1])
                    try:
                        await_condition(received_off,120)
                    except Exception:
                        # Expose only receiver counts, never credentials, device IDs or events.
                        print('Stopped telemetry observation:', {
                            'registrations': fixture.registrations, 'policyRequests': fixture.policy_requests,
                            'sessionRefreshed': any(s['generation']>0 for s in fixture.sessions.values()),
                            'batches': len(fixture.telemetry_receipts)}, flush=True)
                        raise
                    assert len(fixture.sessions)==1 and next(iter(fixture.sessions.values()))['generation']>0
                    assert vpn_stopped() and call('status')['generation']==stopped
                    assert fixture.registrations==1 and call('auth-status')['generation']==generation
                elif name in ('enrolledVersionUpgradeRetainsBindingPolicyAndRealTun','enrolledSystemInstallerCancelKeepsBoundPolicy','enrolledHistoricalUpgradeKeepsOriginalBindingAndPayload'):
                    check_enrolled_upgrade(fixture, proxy, generation, system_installer=installer_only, historical=historical)
                elif name=='enrolledRevocationStopsNativeWithoutLocalFallback':
                    fixture.policy_status=403;call('policy-refresh')
                    await_condition(lambda:call('auth-status').get('phase')=='NEEDS_REAUTH' and
                                    not pid(':engine') and call('status').get('engineActive') is False)
                    assert call('status')['desiredOn'] and call('status')['policy']['managed']
                    observed=proxy.progress;time.sleep(2);assert proxy.progress==observed
                else:
                    call('fault-hang');logout()
                    assert not fixture.sessions and vpn_stopped()
                    entries=adb('shell','run-as',PACKAGE,'ls','no_backup/login/device-login-v1').decode().split()
                    assert entries==['intent.json']
                print(name+': passed',flush=True)
            except Exception:
                try:print('Enrolled failure state: '+json.dumps(failure_summary()),flush=True)
                except Exception:print('Enrolled failure state unavailable',flush=True)
                ET.SubElement(case,'failure',message='enrolled native VPN acceptance failed')
                raise
            finally:
                proxy.delay=0
                logout()
    finally:
        try:logout()
        finally:
            close_fixture();adb('reverse','--remove','tcp:'+str(port));proxy.shutdown();proxy.server_close()
            suite.set('tests',str(len(suite)));suite.set('failures',str(sum(c.find('failure') is not None for c in suite)))
            suite.set('errors','0');suite.set('skipped','0');out.parent.mkdir(parents=True,exist_ok=True);ET.ElementTree(suite).write(out,encoding='utf-8',xml_declaration=True)

if __name__=='__main__':main()
