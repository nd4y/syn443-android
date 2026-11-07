"""Actual TLS/PKCE/DPoP -> controller -> signed policy -> isolated Go/TUN on a disposable emulator."""
import base64
import copy
import json
import subprocess
import threading
import time
import xml.etree.ElementTree as ET
from enrollment_fixture import Fixture
from run_vpn_process_faults import ROOT, PACKAGE, Proxy, Server, adb, call, pid, await_condition
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

def failure_summary():
    state=call('status');auth=call('auth-status');policy=state.get('policy',{})
    phases={'unmanaged','unavailable','blocked','prepared','applying','committed','degraded','rolled_back','rejected','released'}
    safe_policy={'phase':policy.get('phase') if policy.get('phase') in phases else 'unknown'}
    for name in ('activeRevision','lastKnownGoodRevision','candidateRevision','activationGeneration','maxRevision'):
        value=policy.get(name)
        if type(value) is int and 0<=value<=9007199254740991:safe_policy[name]=value
    return {'desiredOn':state.get('desiredOn') is True,'engineActive':state.get('engineActive') is True,
        'intentGeneration':state.get('generation') if type(state.get('generation')) is int else None,
        'policy':safe_policy,'authBusy':auth.get('busy') is True,
        'controllerPresent':bool(pid(':controller')),'nativePresent':bool(pid(':engine'))}

def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish'),'Emulator only'
    assert PACKAGE+'.test/io.syn443.android.EnrollmentDriver' in adb('shell','pm','list','instrumentation').decode(),'Test APK enrollment driver is not installed'
    suite=ET.Element('testsuite',name='SYN443 enrolled native VPN')
    out=ROOT/'app/build/outputs/androidTest-results/external/TEST-enrolled-vpn.xml'
    proxy=Server(('127.0.0.1',0),RouteProxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
    proxy.ssh_ok=True;proxy.delay=0;proxy.health_ok=True;proxy.route_probes=0
    port=proxy.server_address[1];adb('reverse','tcp:'+str(port),'tcp:'+str(port))
    config={'outbounds':[{'type':'http','tag':'enrolled-proxy','server':'127.0.0.1','server_port':port}], 'route':{'final':'enrolled-proxy'}}
    fixture=None
    def stopped():return not pid(':engine') and not call('status').get('engineActive')
    def logout():
        call('auth-cancel');await_condition(lambda:stopped() and call('auth-status').get('phase')=='SIGNED_OUT' and not call('auth-status').get('busy'),40)
    def close_fixture():
        nonlocal fixture
        if fixture:
            adb('reverse','--remove','tcp:'+str(fixture.server.server_port));fixture.close();fixture=None
    def setup(pending=False):
        nonlocal fixture
        logout();close_fixture();call('policy-test-reset');call('test-reset')
        call('import',base64.b64encode(json.dumps(config,separators=(',',':')).encode()).decode())
        call('test-health','synthetic-http');proxy.allowed=True
        fixture=Fixture(config);fixture_port=fixture.server.server_port
        fixture.pending_policy_requests=1 if pending else 0
        adb('reverse','tcp:'+str(fixture_port),'tcp:'+str(fixture_port))
        data=json.dumps(fixture.bootstrap(),separators=(',',':')).encode()
        subprocess.run(['adb','-e','shell','-T','run-as',PACKAGE,'dd','of=no_backup/operator-identity.json'],input=data,capture_output=True,check=True,timeout=15)
        call('auth-bootstrap-file');await_condition(lambda:call('auth-status').get('configured') and not call('auth-status').get('busy'),20)
        driver=subprocess.run(['adb','-e','shell','am','instrument','-w','-e','fixturePort',str(fixture_port),'-e','fixtureCa',fixture.ca,
            PACKAGE+'.test/io.syn443.android.EnrollmentDriver'],capture_output=True,timeout=75)
        result=driver.stdout.decode()
        if driver.returncode or 'synthetic_enrollment_verified' not in result or 'INSTRUMENTATION_CODE: -1' not in result:
            import re
            stage=re.search(r'INSTRUMENTATION_RESULT: stage=([a-z_]{1,40})',result)
            state=call('auth-status');safe={k:v for k,v in state.items() if k in ('phase','reason') and isinstance(v,str) and re.fullmatch('[A-Z_]{0,64}',v)}
            raise AssertionError('Synthetic enrollment failed at '+(stage[1] if stage else 'driver_launch')+' '+json.dumps(safe))
        assert fixture.registrations==1 and not call('status')['desiredOn']
        adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        before=proxy.progress;call('connect')
        await_condition(lambda:call('status').get('phase')=='Online' and call('status').get('policy',{}).get('phase')=='committed' and proxy.progress>before)
    names=['enrolledPendingAssignmentRetriesWhileVisible','enrolledSignedAssignmentStartsRealTun','enrolledControllerDeathRecoversAuthorizedCache',
           'enrolledCandidateRegressionRollsBack','enrolledRevocationStopsNativeWithoutLocalFallback',
           'enrolledLogoutRetiresFrozenNativeBeforeAcknowledging',
           'enrolledAssignedRoutesCommitWithOptionalFailure',
           'enrolledRequiredRouteFailureCannotCommitThroughHealthyInternet',
           'enrolledStopFencesPendingCandidateRouteSuccess']
    def observed_report(revision,outcome,selected):
        return any(r['policyRevision']==revision and r['outcome']==outcome and r['activePolicyRevision']==selected
                   for r in list(fixture.activation_reports.values()))
    try:
        for name in names:
            case=ET.SubElement(suite,'testcase',classname='io.syn443.android.EnrolledVpn',name=name)
            try:
                setup(name=='enrolledPendingAssignmentRetriesWhileVisible');before=proxy.progress;generation=call('auth-status')['generation']
                if name=='enrolledPendingAssignmentRetriesWhileVisible':
                    assert fixture.policy_requests>=2 and fixture.registrations==1
                    assert call('status')['policy']['activeRevision']==1
                elif name=='enrolledSignedAssignmentStartsRealTun':
                    assert call('status')['policy']['activeRevision']==1 and fixture.policy_requests>=1
                    await_condition(lambda:observed_report(1,'committed',1),45)
                    call('disconnect');await_condition(stopped)
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
                    broken=copy.deepcopy(config);broken['outbounds'][0]['server_port']=1;fixture.config=broken;fixture.revision=2
                    call('policy-refresh')
                    await_condition(lambda:call('status').get('policy',{}).get('phase')=='rolled_back' and call('status').get('phase')=='Online' and proxy.progress>before)
                    assert call('status')['policy']['activeRevision']==1
                    await_condition(lambda:observed_report(2,'rolled_back',1),45)
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
                        call('disconnect');await_condition(stopped);generation_after=call('status')['generation'];time.sleep(5)
                        state=call('status')
                        assert not state['desiredOn'] and state['generation']==generation_after and stopped()
                        # A trial permit authorizes only the candidate; the previous active
                        # envelope is intentionally not reported as a usable current permit.
                        assert state['policy']['phase'] in ('applying','rolled_back')
                        assert state['policy'].get('activeRevision') in (None,1)
                        # Prove the durable pointer survived, rather than mistaking an
                        # unavailable runtime-view field for a committed revision.
                        fixture.policy_status=503;controller=pid(':controller');call('fault-controller')
                        await_condition(lambda:stopped_rollback_recovered(controller,generation_after),45)
                        assert call('status')['generation']==generation_after and not call('status')['desiredOn'] and stopped()
                    proxy.delay=0
                elif name=='enrolledRevocationStopsNativeWithoutLocalFallback':
                    fixture.policy_status=403;call('policy-refresh')
                    await_condition(lambda:call('auth-status').get('phase')=='NEEDS_REAUTH' and stopped())
                    assert call('status')['desiredOn'] and call('status')['policy']['managed']
                    observed=proxy.progress;time.sleep(2);assert proxy.progress==observed
                else:
                    call('fault-hang');logout()
                    assert not fixture.sessions and stopped()
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
