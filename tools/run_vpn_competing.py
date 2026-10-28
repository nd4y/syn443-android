"""Real independent test-APK VPN ownership, exclusively on disposable emulators."""
import base64
import json
import threading
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import ROOT,PACKAGE,Server,Proxy,adb,call,pid,await_condition


def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    peer=PACKAGE+'.test'
    component=peer+'/io.syn443.android.acceptance.CompetingVpnActivity'
    suite=ET.Element('testsuite',name='SYN443 competing VPN owner')
    out=ROOT/'app/build/outputs/androidTest-results/external/TEST-vpn-competing.xml'
    case=ET.SubElement(suite,'testcase',classname='io.syn443.android.CompetingVpnTest',name='competingVpnOwnsTunAndRevokesOriginalWithoutRetryFight')
    proxy=Server(('127.0.0.1',0),Proxy);port=str(proxy.server_address[1])
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    def peer_stop():adb('shell','am','start','-W','-n',component,'--ez','ci-stop','true')
    try:
        call('disconnect');await_condition(lambda:not pid(':engine') and not call('status')['engineActive'],30)
        call('policy-test-reset');call('test-reset');peer_stop()
        adb('reverse','tcp:'+port,'tcp:'+port)
        config={'outbounds':[{'type':'http','tag':'test-proxy','server':'127.0.0.1','server_port':int(port)}],'route':{'final':'test-proxy'}}
        call('import',base64.b64encode(json.dumps(config).encode()).decode());call('test-health','synthetic-http');call('connect')
        await_condition(lambda:call('status')['phase']=='Online' and proxy.progress>0)
        before=call('status');old=pid(':engine');assert old
        # Only this disposable-emulator driver preauthorizes the test UID.
        adb('shell','appops','set',peer,'ACTIVATE_VPN','allow')
        adb('shell','am','start','-W','-n',component,'--ez','ci-start','true')
        await_condition(lambda:adb('shell','run-as',peer,'cat','no_backup/competing-vpn-state').strip()==b'active',20)
        await_condition(lambda:call('status')['phase']=='Off' and not call('status')['desiredOn'] and not call('status')['engineActive'] and not pid(':engine'),25)
        revoked=call('status');assert revoked['generation']>before['generation']
        assert any(e['code']=='vpn_permission_revoked' for e in revoked['events'])
        controller=pid(':controller');call('fault-controller');await_condition(lambda:pid(':controller')!=controller,20)
        time.sleep(5)
        persisted=call('status');assert not pid(':engine') and not persisted['desiredOn'] and persisted['generation']==revoked['generation']
        assert persisted['heavyWallMs']==revoked['heavyWallMs']
        peer_stop()
        await_condition(lambda:adb('shell','run-as',peer,'cat','no_backup/competing-vpn-state').strip()==b'off',20)
        adb('shell','appops','set',PACKAGE,'ACTIVATE_VPN','allow')
        progress=proxy.progress;call('connect')
        await_condition(lambda:call('status')['phase']=='Online' and pid(':engine') not in ('',old) and proxy.progress>progress,150)
        assert call('status')['generation']>revoked['generation']
        print(case.get('name')+': passed',flush=True)
    except Exception as error:
        ET.SubElement(case,'failure',message=type(error).__name__).text=str(error);raise
    finally:
        try:
            peer_stop();call('disconnect');call('test-health','production-https')
            await_condition(lambda:not pid(':engine') and not call('status')['engineActive'],30)
        finally:
            adb('reverse','--remove','tcp:'+port);proxy.shutdown();proxy.server_close()
            out.parent.mkdir(parents=True,exist_ok=True);ET.ElementTree(suite).write(out,encoding='utf-8',xml_declaration=True)


if __name__=='__main__':main()
