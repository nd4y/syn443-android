"""Emulator-only actual routes, package replacement, locked boot and system policy.
All targets and the disposable emulator PIN are synthetic. No physical credential changes.
"""
import base64
import hashlib
import json
import os
import re
import socketserver
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import ROOT, PACKAGE, URI, Server, Proxy, ControlUnavailable, adb, call, pid, await_condition, vpn_stopped
from emulator_policy_ui import open_policy, toggle, unlock_test_pin
from emulator_boot import reboot_preserved
from syn443ctl import ControlError, Device


class RouteProxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5);stream=self.request.makefile('rb')
        line=stream.readline(4096);Proxy.headers(stream)
        if line.startswith((b'CONNECT 203.0.113.10:80 ', b'CONNECT 203.0.113.11:80 ')):
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            request = stream.readline(4096)
            challenge = getattr(self.server, 'start_challenge', None)
            if challenge and request == b'GET /syn443-start/' + challenge + b' HTTP/1.1\r\n':
                Proxy.headers(stream)
                self.request.sendall(b'HTTP/1.1 204 No Content\r\nX-Syn443-Start: ' + challenge +
                                     b'\r\nConnection: close\r\n\r\n')
                return
            if request.startswith(b'GET /syn443-payload '):
                received = getattr(self.server, 'payload_received', None)
                Proxy.headers(stream)
                if received is not None:
                    received.set()
                    if getattr(self.server, 'refuse_payload', False):
                        self.request.sendall(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
                        return
                    self.request.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n')
            elif request.startswith(b'GET /generate_204 '):
                Proxy.headers(stream)
                self.request.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n' if self.server.health_ok else b'HTTP/1.1 503 Unavailable\r\nContent-Length: 0\r\n\r\n')
                self.server.progress+=1
        elif line.startswith(b'CONNECT 192.0.2.9:22 '):
            self.server.route_probes+=1;self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            time.sleep(self.server.delay)
            self.request.sendall(b'SSH-2.0-synthetic\r\n' if self.server.ssh_ok else b'wrong-protocol\r\n')



def exchange_through_proxy(proxy, destination="203.0.113.10", *, expected_status=204):
    assert expected_status in (204, 503)
    assert destination in ("203.0.113.10", "203.0.113.11")
    # Keep the client half-open while the application UID reads the reply.
    # A pipe directly into toybox nc can close its input before the peer responds.
    proxy.payload_received = threading.Event()
    try:
        command = (r"(printf 'GET /syn443-payload HTTP/1.1\r\nHost: fixture.invalid\r\n"
                   r"Connection: close\r\n\r\n'; sleep 3) | run-as " + PACKAGE +
                   f" toybox nc -w 5 {destination} 80")
        response = adb('shell', '-T', command, timeout=12)
        confirmed = proxy.payload_received.wait(1)
        status = re.match(rb'HTTP/1\.1 ([0-9]{3}) ', response)
        if not confirmed or status is None or int(status[1]) != expected_status:
            raise AssertionError('Application payload: expected proxy received=%s, HTTP status=%s' %
                                 (confirmed, status[1].decode() if status else 'absent'))
    finally:
        proxy.payload_received = None


def completed_route_batch():
    # Online is independent HTTPS health, not completion of every outbound probe.
    report=call('routes-status')
    rows=report.get('routes')
    assert isinstance(rows,list) and [r.get('id') for r in rows]==['route-1','route-2','route-3'], 'Unexpected route batch membership'
    expected=['working','failed','working']
    pending=False
    for row,state in zip(rows,expected):
        observed=row.get('state')
        if observed in ('checking','unknown','unavailable'):
            pending=True
            continue
        assert observed==state, 'A completed route has an unexpected outcome'
        age=row.get('ageMs')
        assert type(age) is int and 0<=age<=35_000, 'Route evidence is missing or stale'
    if pending or report.get('running') is True:
        return False
    assert report.get('running') is False and report.get('requiredReady') is True, 'Route batch has no completion proof'
    assert rows[2].get('measuredPath')==['route-3','route-1'], 'Selector probe did not traverse its actual selected outbound'
    return True


def wifi_loss_recovery(proxy):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('SYN443_CI_AVD') != 'syn443-ci'
            or adb('emu', 'avd', 'name').splitlines() != [b'syn443-ci', b'OK']):
        raise ValueError('Disposable Wi-Fi emulator required')
    assert adb('shell', 'settings', 'get', 'global', 'mobile_data').strip() == b'0', 'Cellular data must already be disabled'

    def online_after(epoch):
        current = call('status')
        physical = current.get('physicalLink') or {}
        if current.get('phase') != 'Online' or physical.get('transport') != 'WIFI':
            return None
        return current if current['networkEpoch'] > epoch else None

    await_condition(lambda: online_after(-1), 25)
    before = online_after(-1)
    assert before is not None and before['desiredOn'] and completed_route_batch()
    exchange_through_proxy(proxy)

    def offline():
        current = call('status')
        assert current['desiredOn'] and current['generation'] == before['generation']
        assert current['configRevision'] == before['configRevision']
        if current['phase'] != 'NoNetwork':
            return None
        routes = call('routes-status')
        assert current['reason'] == 'network_unavailable' and current.get('physicalLink') is None
        assert current['networkEpoch'] > before['networkEpoch']
        assert routes['running'] is False and routes['requiredReady'] is False
        assert routes['routes'] and all(row['state'] != 'working' for row in routes['routes'])
        return current

    adb('shell', 'svc', 'wifi', 'disable')
    try:
        await_condition(offline, 35)
        lost = offline()
        assert lost is not None
        traffic = (proxy.progress, proxy.route_probes)
        # Observe longer than the early health-probe throttle. No available
        # underlay may publish old checks or initiate a new request.
        end = time.monotonic() + 6
        while time.monotonic() < end:
            current = offline()
            assert current and current['networkEpoch'] == lost['networkEpoch']
            assert (proxy.progress, proxy.route_probes) == traffic
            time.sleep(1)
    finally:
        adb('shell', 'svc', 'wifi', 'enable')

    after = None
    def recovered():
        nonlocal after
        after = online_after(lost['networkEpoch'])
        return after is not None and completed_route_batch()

    await_condition(recovered, 90)
    assert after['desiredOn'] and after['generation'] == before['generation']
    assert after['configRevision'] == before['configRevision']
    assert proxy.progress > traffic[0] and proxy.route_probes > traffic[1]
    exchange_through_proxy(proxy)


def resume_blocked(before):
    # Activity drawn is earlier than VpnControls' asynchronous foreground-open.
    # Observe that completion, while failing immediately on any unsafe state.
    snapshot=call('status')
    assert not pid(':engine'),'Unexpected native owner after Force stop/update'
    assert snapshot['engineActive'] is not True, 'Saved engine checkpoint leaked into current status'
    assert snapshot['configRevision']==before['configRevision'],'Configuration changed after Force stop/update'
    assert snapshot['generation']==before['generation'],'Intent generation changed after Force stop/update'
    assert snapshot['desiredOn'] is True,'Desired intent changed after Force stop/update'
    if snapshot.get('resumeRequired') is not True:
        return False
    return snapshot['engineActive'] is False and snapshot.get('engineStateKnown') is True


def locked_boot_boundary():
    # Check the engine independently of the provider. Unavailable ADB status
    # may be transient; a native owner before unlock is an immediate failure.
    assert not pid(':engine'), 'Unexpected native owner before first unlock'
    snapshot=call('status')
    assert not snapshot.get('engineActive'), 'Engine active before first unlock'
    if snapshot.get('phase')!='NeedsUnlock':
        return False
    assert snapshot['engineActive'] is False, 'Locked status must explicitly report no active engine'
    assert snapshot['desiredOn'] is None and not snapshot['desiredOnKnown'], 'Credential intent disclosed before first unlock'
    return True


def off_after_reboot(before):
    # Sample the native process even when the provider is still starting.
    try:
        native = pid(':engine', timeout=5)
    except ControlUnavailable as error:
        raise AssertionError('Multiple native engines after reboot with VPN Off') from error
    assert not native, 'Native engine started after reboot with VPN Off'
    try:
        state = call('status', timeout=5)
    except subprocess.TimeoutExpired:
        return False
    assert state.get('engineActive') is not True, 'Active engine after reboot with VPN Off'
    if state.get('phase') == 'NeedsUnlock' and state.get('desiredOnKnown') is False:
        assert state.get('desiredOn') is None, 'Locked status exposed an intent'
        return False
    assert state['desiredOn'] is False, 'VPN Off intent changed during reboot'
    assert state['generation'] == before['generation'], 'VPN intent generation changed during reboot'
    assert state['configRevision'] == before['configRevision'], 'Configuration changed during reboot'
    assert state.get('heavyWallMs', []) == before.get('heavyWallMs', []), 'Restart budget changed during reboot'
    assert state['phase'] == 'Off', 'Unexpected VPN phase after reboot with VPN Off'
    return state.get('engineStateKnown') is True and state.get('engineActive') is False


def direct_boot_diagnostics():
    # The caller runs only on the disposable emulator. Keep output to bounded
    # classifications so errors never emit arbitrary ADB payloads.
    def probe(*args):
        try:return adb(*args,timeout=5).decode(errors='replace').strip()
        except subprocess.CalledProcessError as error:return error.output.decode(errors='replace').strip()
        except subprocess.TimeoutExpired:return ''
    user=probe('shell','am','get-started-user-state','0')
    package=probe('shell','pm','path',PACKAGE)
    controller=probe('shell','pidof',PACKAGE+':controller')
    raw=probe('shell','content','call','--uri',URI,'--method','status')
    if 'Permission Denial' in raw or 'SecurityException' in raw:control='denied'
    elif 'No content provider found' in raw or 'Could not find provider' in raw:control='missing'
    elif 'Error while accessing provider' in raw or 'DeadObjectException' in raw:control='binder_error'
    elif 'ok=true' in raw:control='answered'
    else:control='unknown'
    return {'user0State':user if user in ('BOOTING','RUNNING_LOCKED','RUNNING_UNLOCKING','RUNNING_UNLOCKED') else 'unknown',
            'packagePresent':package.startswith('package:'),'controllerPresent':controller.isdigit(),'control':control}


def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    suite=ET.Element('testsuite',name='SYN443 route and Android lifecycle')
    out=ROOT/'app/build/outputs/androidTest-results/external/TEST-route-lifecycle.xml'
    servers=[Server(('127.0.0.1',0),RouteProxy) for _ in range(2)]
    for index,server in enumerate(servers):
        server.ssh_ok=index==0;server.route_probes=0;server.delay=0;server.health_ok=True
        threading.Thread(target=server.serve_forever,daemon=True).start()
    ports=[str(s.server_address[1]) for s in servers]
    config={'outbounds':[{'type':'http','tag':'working','server':'127.0.0.1','server_port':int(ports[0])},
                         {'type':'http','tag':'optional','server':'127.0.0.1','server_port':int(ports[1])},
                         {'type':'selector','tag':'balanced','outbounds':['working','optional'],'default':'working'}],
            'route':{'final':'working'},'route_checks':[
                {'outbound':'working','required':True,'checks':[{'method':'ssh_banner','target':'192.0.2.9:22'}]},
                {'outbound':'optional','checks':[{'method':'ssh_banner','target':'192.0.2.9:22'}]},
                {'outbound':'balanced','checks':[{'method':'ssh_banner','target':'192.0.2.9:22'}]}]}
    raw=json.dumps(config);case=None;pin_set=False;policy_set=False
    def forward():
        for port in ports:adb('reverse','tcp:'+port,'tcp:'+port)
    def stop():
        call('disconnect');await_condition(vpn_stopped,30)
    def prepare():
        stop();call('policy-test-reset');call('test-reset');servers[0].ssh_ok=True;servers[0].delay=0;servers[0].health_ok=True
        adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        call('import',base64.b64encode(raw.encode()).decode());call('test-health','synthetic-http');forward()
        call('connect');await_condition(lambda:call('status')['phase']=='Online' and servers[0].progress>0,150)
        await_condition(completed_route_batch,35)
    def row(index):return call('routes-status')['routes'][index]
    def reboot():
        reboot_preserved(adb);forward()
    def new_case(name):return ET.SubElement(suite,'testcase',classname='io.syn443.android.RouteLifecycleTest',name=name)
    try:
        case=new_case('adbLocalConfigPreviewDoesNotWriteAndApplyFencesStaleBase')
        stop();call('policy-test-reset')
        device=Device(adb('get-serialno').decode().strip(),15)
        before=call('status')
        base=before.get('configRevision') or 'none'
        payload=raw.encode()
        candidate=hashlib.sha256(payload).hexdigest()
        if candidate==base:
            payload+=b'\n';candidate=hashlib.sha256(payload).hexdigest()
        plan=device.config('config-plan',payload,base,candidate)
        assert plan['different'] and not plan['written'] and plan['currentRevision']==base
        assert (call('status').get('configRevision') or 'none')==base
        receipt=device.config('config-apply',payload,base,candidate)
        assert receipt['written'] and receipt['currentRevision']==candidate
        for expected,digest in [(base,candidate),(candidate,'f'*64)]:
            try:device.config('config-apply',payload,expected,digest)
            except ControlError as error:assert error.code=='command_rejected'
            else:raise AssertionError('stale or mismatched local configuration was accepted')
        after=call('status')
        assert after['configRevision']==candidate and after['generation']==before['generation'] and not after['desiredOn']
        print(case.get('name')+': passed',flush=True)

        case=new_case('routeChecksUseActualOutboundsAndSelectedProxy')
        prepare();assert completed_route_batch()
        assert row(2)['measuredPath']==['route-3','route-1'] and all(s.route_probes>0 for s in servers)
        controller=pid(':controller')
        try:call('routes-check','route-99')
        except AssertionError:pass
        else:raise AssertionError('Unknown route command was accepted')
        assert pid(':controller')==controller and call('status')['phase']=='Online'
        print(case.get('name')+': passed',flush=True)

        case=new_case('requiredRouteFailureDegradesWithoutRestartAndRecovers')
        before=pid(':engine');servers[0].ssh_ok=False;call('routes-check')
        await_condition(lambda:row(0)['state']=='failed' and call('status')['phase']=='Degraded',40)
        assert pid(':engine')==before and call('status')['desiredOn']
        servers[0].ssh_ok=True;call('routes-check')
        await_condition(lambda:row(0)['state']=='working' and call('status')['phase']=='Online',40);assert pid(':engine')==before
        servers[0].health_ok=False
        await_condition(lambda:call('status')['phase']=='Degraded',40)
        assert row(0)['state']=='working' and pid(':engine')==before
        servers[0].health_ok=True
        await_condition(lambda:call('status')['phase']=='Online',90)
        assert pid(':engine')==before
        print(case.get('name')+': passed',flush=True)

        case=new_case('physicalWiFiLossInvalidatesRoutesAndRecoversPayloadWithoutNewIntent')
        wifi_loss_recovery(servers[0])
        print(case.get('name')+': passed',flush=True)

        case=new_case('stopCancelsPendingRouteChecksAndRejectsLateSuccess')
        servers[0].delay=2;call('routes-check');stop();generation=call('status')['generation'];time.sleep(4)
        assert call('status')['phase']=='Off' and call('status')['generation']==generation
        assert all(r['state']=='off' for r in call('routes-status')['routes'])
        print(case.get('name')+': passed',flush=True)

        case=new_case('packageUpdatePreservesConfigIntentAndOffAcrossSystemCallback')
        prepare();stop();before=call('status');adb('install','-r',str(ROOT/'app/build/outputs/apk/debug/app-debug.apk'),timeout=120)
        time.sleep(5);after=call('status')
        assert after['configRevision']==before['configRevision'] and after['generation']==before['generation']
        assert not after['desiredOn'] and not pid(':engine')
        print(case.get('name')+': passed',flush=True)

        # The system settings UI belongs to this case. Finish it on the running
        # image before either independent direct-boot scenario reboots Android.
        case=new_case('actualAlwaysOnLockdownRespectsNewerStop')
        prepare();open_policy();toggle('Always-on VPN',True);policy_set=True;toggle('Block connections without VPN',True)
        await_condition(lambda:call('status').get('osPolicy',{}).get('alwaysOn') and call('status').get('osPolicy',{}).get('lockdown'),40)
        stop();before=call('status');time.sleep(8)
        assert not pid(':engine') and not call('status')['desiredOn'] and call('status')['generation']==before['generation']
        toggle('Block connections without VPN',False);toggle('Always-on VPN',False);policy_set=False
        adb('shell','input','keyevent','KEYCODE_BACK');assert not call('status')['desiredOn']
        print(case.get('name')+': passed',flush=True)

        case=new_case('rebootBeforeUnlockDoesNotReadCredentialStateThenReconciles')
        prepare();before=call('status')
        adb('shell','input','keyevent','KEYCODE_HOME')
        answer=adb('shell','locksettings','set-pin','2468');assert b'set to' in answer.lower();pin_set=True
        reboot()
        try:await_condition(locked_boot_boundary,60)
        except Exception:
            print('Direct boot boundary: '+json.dumps(direct_boot_diagnostics()),flush=True)
            raise
        progress_before_unlock=servers[0].progress
        unlock_test_pin()
        # Reading the debug app's persisted test state does not initialize its
        # provider. Wait for an actual HTTP response and a fresh service-owned
        # Online event before deliberately making the first unlocked status call.
        online_sequence=0
        def booted_service_online():
            nonlocal online_sequence
            if servers[0].progress<=progress_before_unlock or not pid(':engine'):return False
            try:
                durable=json.loads(adb('shell','run-as',PACKAGE,'cat','no_backup/vpn-intent.json'))
            except (subprocess.CalledProcessError, json.JSONDecodeError):
                return False
            online_sequence=max((event['sequence'] for event in durable.get('events',[])
                                 if event.get('phase')=='Online' and event.get('intentGeneration')==before['generation']),default=0)
            return durable['generation']==before['generation'] and durable.get('phase')=='Online' and online_sequence>before['eventSequence']
        await_condition(booted_service_online,150)
        case=new_case('firstUnlockedStatusPreservesTheAlreadyRecoveredVpnPhase')
        def first_read():
            state=call('status')
            assert state.get('osPolicy',{}).get('unlocked') is True
            assert state['phase']=='Online' and state['engineActive'] is True
            assert not any(event['sequence']>online_sequence and event.get('code')=='controller_recreated'
                           for event in state.get('events',[]))
            return True
        await_condition(first_read,30)
        after=call('status');assert after['configRevision']==before['configRevision'] and after['generation']==before['generation']
        assert set(before.get('heavyWallMs',[])).issubset(after.get('heavyWallMs',[]))
        adb('shell','locksettings','clear','--old','2468');pin_set=False
        print(case.get('name')+': passed',flush=True)

        case=new_case('rebootWithOffIntentCannotStartOrSpendBudget')
        stop()
        before = call('status')
        reboot()
        observe_until = time.monotonic() + 5
        await_condition(lambda: off_after_reboot(before) and time.monotonic() >= observe_until, 30)
        print(case.get('name')+': passed',flush=True)

        case=new_case('forceStopThenPackageUpdateCannotResumeWithoutUserConnect')
        prepare();before=call('status');adb('shell','am','force-stop',PACKAGE)
        adb('install','-r',str(ROOT/'app/build/outputs/apk/debug/app-debug.apk'),timeout=120)
        time.sleep(5);assert not pid(':engine');adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        await_condition(lambda:resume_blocked(before),30);after=call('status')
        assert after['generation']==before['generation'];call('connect');await_condition(lambda:call('status')['phase']=='Online',150)
        print(case.get('name')+': passed',flush=True)
    except Exception as error:
        try:
            snapshot=call('status')
            print('Route lifecycle failure state: '+json.dumps({k:snapshot.get(k) for k in ('phase','reason','desiredOn','generation','resumeRequired','osPolicy')}),flush=True)
            print('Route lifecycle evidence: '+json.dumps([{k:r.get(k) for k in ('id','state','reason')} for r in snapshot.get('routeHealth',{}).get('routes',[])]),flush=True)
        except Exception as diagnostic:print('Route lifecycle diagnostic unavailable: '+type(diagnostic).__name__,flush=True)
        if case is not None:ET.SubElement(case,'failure',message=type(error).__name__).text=str(error)
        raise
    finally:
        try:
            if policy_set:open_policy();toggle('Block connections without VPN',False);toggle('Always-on VPN',False)
            if pin_set:adb('shell','locksettings','clear','--old','2468')
            stop();call('test-health','production-https')
        finally:
            for server,port in zip(servers,ports):
                adb('reverse','--remove','tcp:'+port);server.shutdown();server.server_close()
            out.parent.mkdir(parents=True,exist_ok=True);ET.ElementTree(suite).write(out,encoding='utf-8',xml_declaration=True)


if __name__=='__main__':main()
