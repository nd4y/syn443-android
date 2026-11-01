"""Emulator-only actual routes, package replacement, locked boot and system policy.
All targets and the disposable emulator PIN are synthetic. No physical credential changes.
"""
import base64
import json
import re
import socketserver
import threading
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import ROOT, PACKAGE, Server, Proxy, adb, call, pid, await_condition
from emulator_policy_ui import open_policy, toggle


class RouteProxy(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(5);stream=self.request.makefile('rb')
        line=stream.readline(4096);Proxy.headers(stream)
        if line.startswith(b'CONNECT 203.0.113.10:80 '):
            self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            if stream.readline(4096).startswith(b'GET /generate_204 '):
                Proxy.headers(stream);self.request.sendall(b'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n');self.server.progress+=1
        elif line.startswith(b'CONNECT 192.0.2.9:22 '):
            self.server.route_probes+=1;self.request.sendall(b'HTTP/1.1 200 Connection established\r\n\r\n')
            time.sleep(self.server.delay)
            self.request.sendall(b'SSH-2.0-synthetic\r\n' if self.server.ssh_ok else b'wrong-protocol\r\n')


def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    suite=ET.Element('testsuite',name='SYN443 route and Android lifecycle')
    out=ROOT/'app/build/outputs/androidTest-results/external/TEST-route-lifecycle.xml'
    servers=[Server(('127.0.0.1',0),RouteProxy) for _ in range(2)]
    for index,server in enumerate(servers):
        server.ssh_ok=index==0;server.route_probes=0;server.delay=0
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
        call('disconnect');await_condition(lambda:not pid(':engine') and not call('status')['engineActive'],30)
    def prepare():
        stop();call('policy-test-reset');call('test-reset');servers[0].ssh_ok=True;servers[0].delay=0
        adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        call('import',base64.b64encode(raw.encode()).decode());call('test-health','synthetic-http');forward()
        call('connect');await_condition(lambda:call('status')['phase']=='Online' and servers[0].progress>0,150)
    def row(index):return call('routes-status')['routes'][index]
    def reboot():
        adb('reboot');adb('wait-for-device',timeout=150)
        await_condition(lambda:adb('shell','getprop','sys.boot_completed').strip()==b'1',150);forward()
    def new_case(name):return ET.SubElement(suite,'testcase',classname='io.syn443.android.RouteLifecycleTest',name=name)
    try:
        case=new_case('routeChecksUseActualOutboundsAndSelectedProxy')
        prepare();assert row(0)['state']=='working' and row(1)['state']=='failed' and row(2)['state']=='working'
        assert row(2)['measuredPath']==['route-3','route-1'] and all(s.route_probes>0 for s in servers)
        print(case.get('name')+': passed',flush=True)

        case=new_case('requiredRouteFailureDegradesWithoutRestartAndRecovers')
        before=pid(':engine');servers[0].ssh_ok=False;call('routes-check')
        await_condition(lambda:row(0)['state']=='failed' and call('status')['phase']=='Degraded',40)
        assert pid(':engine')==before and call('status')['desiredOn']
        servers[0].ssh_ok=True;call('routes-check')
        await_condition(lambda:row(0)['state']=='working' and call('status')['phase']=='Online',40);assert pid(':engine')==before
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

        case=new_case('rebootBeforeUnlockDoesNotReadCredentialStateThenReconciles')
        prepare();before=call('status')
        answer=adb('shell','locksettings','set-pin','2468');assert b'set to' in answer.lower();pin_set=True
        reboot();await_condition(lambda:call('status').get('phase')=='NeedsUnlock',60)
        locked=call('status');assert locked['desiredOn'] is None and not locked['desiredOnKnown'] and not locked['engineActive'] and not pid(':engine')
        adb('shell','input','keyevent','KEYCODE_WAKEUP')
        width,height=map(int,re.findall(r'(\d+)x(\d+)',adb('shell','wm','size').decode())[-1])
        adb('shell','input','swipe',str(width//2),str(height*9//10),str(width//2),str(height//3),'300')
        adb('shell','input','text','2468');adb('shell','input','keyevent','KEYCODE_ENTER')
        await_condition(lambda:call('status').get('phase')=='Online',150)
        after=call('status');assert after['configRevision']==before['configRevision'] and after['generation']==before['generation']
        assert set(before.get('heavyWallMs',[])).issubset(after.get('heavyWallMs',[]))
        adb('shell','locksettings','clear','--old','2468');pin_set=False
        print(case.get('name')+': passed',flush=True)

        case=new_case('rebootWithOffIntentCannotStartOrSpendBudget')
        stop();before=call('status');reboot();time.sleep(5);after=call('status')
        assert not after['desiredOn'] and not pid(':engine') and after['generation']==before['generation']
        assert after.get('heavyWallMs',[])==before.get('heavyWallMs',[]) and after['configRevision']==before['configRevision']
        print(case.get('name')+': passed',flush=True)

        case=new_case('actualAlwaysOnLockdownRespectsNewerStop')
        prepare();open_policy();toggle('Always-on VPN',True);policy_set=True;toggle('Block connections without VPN',True)
        await_condition(lambda:call('status').get('osPolicy',{}).get('alwaysOn') and call('status').get('osPolicy',{}).get('lockdown'),40)
        stop();before=call('status');time.sleep(8)
        assert not pid(':engine') and not call('status')['desiredOn'] and call('status')['generation']==before['generation']
        toggle('Block connections without VPN',False);toggle('Always-on VPN',False);policy_set=False
        adb('shell','input','keyevent','KEYCODE_BACK');assert not call('status')['desiredOn']
        print(case.get('name')+': passed',flush=True)

        case=new_case('forceStopThenPackageUpdateCannotResumeWithoutUserConnect')
        prepare();before=call('status');adb('shell','am','force-stop',PACKAGE)
        adb('install','-r',str(ROOT/'app/build/outputs/apk/debug/app-debug.apk'),timeout=120)
        time.sleep(5);assert not pid(':engine');adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        after=call('status');assert after['resumeRequired'] and not pid(':engine') and after['configRevision']==before['configRevision']
        assert after['generation']==before['generation'];call('connect');await_condition(lambda:call('status')['phase']=='Online',150)
        print(case.get('name')+': passed',flush=True)
    except Exception as error:
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
