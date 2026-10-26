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

def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish'),'Emulator only'
    suite=ET.Element('testsuite',name='SYN443 enrolled native VPN')
    out=ROOT/'app/build/outputs/androidTest-results/external/TEST-enrolled-vpn.xml'
    proxy=Server(('127.0.0.1',0),Proxy);threading.Thread(target=proxy.serve_forever,daemon=True).start()
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
    def setup():
        nonlocal fixture
        logout();close_fixture();call('policy-test-reset');call('test-reset')
        call('import',base64.b64encode(json.dumps(config,separators=(',',':')).encode()).decode())
        call('test-health','synthetic-http');proxy.allowed=True
        fixture=Fixture(config);fixture_port=fixture.server.server_port
        adb('reverse','tcp:'+str(fixture_port),'tcp:'+str(fixture_port))
        data=json.dumps(fixture.bootstrap(),separators=(',',':')).encode()
        subprocess.run(['adb','-e','shell','-T','run-as',PACKAGE,'dd','of=no_backup/operator-identity.json'],input=data,capture_output=True,check=True,timeout=15)
        call('auth-bootstrap-file');await_condition(lambda:call('auth-status').get('configured') and not call('auth-status').get('busy'),20)
        result=adb('shell','am','instrument','-w','-e','fixturePort',str(fixture_port),'-e','fixtureCa',fixture.ca,
            PACKAGE+'.test/io.syn443.android.EnrollmentDriver',timeout=75).decode()
        assert 'synthetic_enrollment_verified' in result and 'INSTRUMENTATION_CODE: -1' in result,'Synthetic enrollment did not complete'
        assert fixture.registrations==1 and not call('status')['desiredOn']
        adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        before=proxy.progress;call('connect')
        await_condition(lambda:call('status').get('phase')=='Online' and call('status').get('policy',{}).get('phase')=='committed' and proxy.progress>before)
    names=['enrolledSignedAssignmentStartsRealTun','enrolledControllerDeathRecoversAuthorizedCache',
           'enrolledCandidateRegressionRollsBack','enrolledRevocationStopsNativeWithoutLocalFallback',
           'enrolledLogoutRetiresFrozenNativeBeforeAcknowledging']
    try:
        for name in names:
            case=ET.SubElement(suite,'testcase',classname='io.syn443.android.EnrolledVpn',name=name)
            try:
                setup();before=proxy.progress;generation=call('auth-status')['generation']
                if name=='enrolledSignedAssignmentStartsRealTun':
                    assert call('status')['policy']['activeRevision']==1 and fixture.policy_requests>=1
                    try:call('import',base64.b64encode(json.dumps(config).encode()).decode());raise RuntimeError('managed import unexpectedly accepted')
                    except AssertionError:pass
                elif name=='enrolledControllerDeathRecoversAuthorizedCache':
                    fixture.policy_status=503;call('fault-controller')
                    await_condition(lambda:call('auth-status').get('generation')==generation and call('status').get('phase')=='Online' and proxy.progress>before)
                    assert fixture.registrations==1
                elif name=='enrolledCandidateRegressionRollsBack':
                    broken=copy.deepcopy(config);broken['outbounds'][0]['server_port']=1;fixture.config=broken;fixture.revision=2
                    call('policy-refresh')
                    await_condition(lambda:call('status').get('policy',{}).get('phase')=='rolled_back' and call('status').get('phase')=='Online' and proxy.progress>before)
                    assert call('status')['policy']['activeRevision']==1
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
                ET.SubElement(case,'failure',message='enrolled native VPN acceptance failed')
                raise
            finally:
                logout()
    finally:
        try:logout()
        finally:
            close_fixture();adb('reverse','--remove','tcp:'+str(port));proxy.shutdown();proxy.server_close()
            suite.set('tests',str(len(suite)));suite.set('failures',str(sum(c.find('failure') is not None for c in suite)))
            suite.set('errors','0');suite.set('skipped','0');out.parent.mkdir(parents=True,exist_ok=True);ET.ElementTree(suite).write(out,encoding='utf-8',xml_declaration=True)

if __name__=='__main__':main()
