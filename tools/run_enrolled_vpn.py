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
from enrollment_fixture import Fixture
from run_vpn_process_faults import ROOT, PACKAGE, Proxy, Server, adb, call, pid, await_condition, vpn_stopped
from run_route_lifecycle import RouteProxy

def stopped_rollback_recovered(controller,generation):
    # A provider read is the explicit recreation request. An empty PID must
    # never short-circuit that read when no foreground UI is polling for us.
    state=call('status')
    assert not state['desiredOn'] and state['generation']==generation
    assert not pid(':engine'),'Stop allowed an unexpected replacement native owner'
    return (pid(':controller') not in ('',controller) and state.get('engineActive') is False and
        state['policy']['phase']=='rolled_back' and state['policy'].get('activeRevision')==1 and
        not call('auth-status')['busy'])

def upgrade_directory(system_installer):
    return Path(os.environ['RUNNER_TEMP']) / ('syn443-installer-private' if system_installer else 'upgrade-fixture')


def check_enrolled_upgrade(fixture, proxy, auth_generation, system_installer=False):
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('SYN443_CI_AVD') != 'syn443-ci'
            or adb('emu', 'avd', 'name').splitlines() != [b'syn443-ci', b'OK']):
        raise ValueError('This APK upgrade requires the disposable CI emulator')
    directory = upgrade_directory(system_installer)
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
    assert b'Success' in response.splitlines() and installed_version() == receipt['previous'] + 1
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
        'controllerPresent':bool(pid(':controller')),'nativePresent':bool(pid(':engine'))}

def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish'),'Emulator only'
    assert PACKAGE+'.test/io.syn443.android.EnrollmentDriver' in adb('shell','pm','list','instrumentation').decode(),'Test APK enrollment driver is not installed'
    suite=ET.Element('testsuite',name='SYN443 enrolled native VPN')
    args=sys.argv[1:]
    if args not in ([], ['--system-installer']):
        raise ValueError('Unexpected enrollment scenario')
    installer_only=bool(args)
    out=(Path(os.environ['RUNNER_TEMP'])/'syn443-installer-private'/'result.xml' if installer_only
         else ROOT/'app/build/outputs/androidTest-results/external/TEST-enrolled-vpn.xml')
    proxy=Server(('127.0.0.1',0),RouteProxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    proxy.ssh_ok=True;proxy.delay=0;proxy.health_ok=True;proxy.route_probes=0
    port=proxy.server_address[1];adb('reverse','tcp:'+str(port),'tcp:'+str(port))
    config={'outbounds':[{'type':'http','tag':'enrolled-proxy','server':'127.0.0.1','server_port':port}], 'route':{'final':'enrolled-proxy'}}
    fixture=None
    def logout():
        call('auth-cancel');await_condition(lambda:vpn_stopped() and call('auth-status').get('phase')=='SIGNED_OUT' and not call('auth-status').get('busy'),40)
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
        logout();close_fixture();call('policy-test-reset');call('test-reset')
        call('import',base64.b64encode(json.dumps(config,separators=(',',':')).encode()).decode())
        call('test-health','synthetic-http');proxy.allowed=True
        fixture=Fixture(config,assigned_device=device);fixture_port=fixture.server.server_port
        fixture.telemetry_enabled=telemetry is not None
        fixture.pending_policy_requests=1 if pending else 0
        adb('reverse','tcp:'+str(fixture_port),'tcp:'+str(fixture_port))
        data=json.dumps(fixture.bootstrap(),separators=(',',':')).encode()
        subprocess.run(['adb','-e','shell','-T','run-as',PACKAGE,'dd','of=no_backup/operator-identity.json'],input=data,capture_output=True,check=True,timeout=15)
        call('auth-bootstrap-file');await_condition(lambda:call('auth-status').get('configured') and not call('auth-status').get('busy'),20)
        before=proxy.progress
        driver=subprocess.run(['adb','-e','shell','am','instrument','-w','-e','fixturePort',str(fixture_port),'-e','fixtureCa',fixture.ca,
            *(['-e','fixtureTelemetry','stopped' if telemetry=='stopped' else 'true'] if telemetry else []),
            PACKAGE+'.test/io.syn443.android.EnrollmentDriver'],capture_output=True,timeout=150 if telemetry=='stopped' else 75)
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
    names=['enrolledPendingAssignmentRetriesWhileVisible','enrolledSignedAssignmentStartsRealTun','enrolledControllerDeathRecoversAuthorizedCache',
           'enrolledCandidateRegressionRollsBack','enrolledRevocationStopsNativeWithoutLocalFallback',
           'enrolledLogoutRetiresFrozenNativeBeforeAcknowledging',
           'enrolledAssignedRoutesCommitWithOptionalFailure',
           'enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet',
           'enrolledStopFencesPendingCandidateRouteSuccess','enrolledStoppedTelemetryUsesScheduledWorkWithoutRevivingVpn',
           'enrolledVersionUpgradeRetainsBindingPolicyAndRealTun']
    if installer_only:
        names=['enrolledSystemInstallerCancelKeepsBoundPolicy']
    def observed_report(revision,outcome,selected):
        return any(r['policyRevision']==revision and r['outcome']==outcome and r['activePolicyRevision']==selected
                   for r in list(fixture.activation_reports.values()))
    try:
        for name in names:
            case=ET.SubElement(suite,'testcase',classname='io.syn443.android.EnrolledVpn',name=name)
            try:
                telemetry_modes={'enrolledCandidateRegressionRollsBack':'foreground',
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
                elif name=='enrolledControllerDeathRecoversAuthorizedCache':
                    old_controller=pid(':controller');old_engine=pid(':engine');assert old_controller and old_engine
                    fixture.policy_status=503;call('fault-controller')
                    await_condition(lambda:bool(pid(':controller')) and pid(':controller')!=old_controller and bool(pid(':engine')) and pid(':engine')!=old_engine)
                    before=proxy.progress
                    await_condition(lambda:call('auth-status').get('generation')==generation and call('status').get('phase')=='Online' and proxy.progress>before)
                    assert fixture.registrations==1
                elif name=='enrolledCandidateRegressionRollsBack':
                    await_condition(lambda:bool(fixture.telemetry_receipts),330)
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
                    due=time.monotonic()+int(until_eligible[1])/1000
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
                    await_condition(received_off,120)
                    assert vpn_stopped() and call('status')['generation']==stopped
                    assert fixture.registrations==1 and call('auth-status')['generation']==generation
                elif name in ('enrolledVersionUpgradeRetainsBindingPolicyAndRealTun','enrolledSystemInstallerCancelKeepsBoundPolicy'):
                    check_enrolled_upgrade(fixture, proxy, generation, system_installer=installer_only)
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
