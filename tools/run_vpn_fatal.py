"""Disposable emulator: actual uncaught Java/Go faults, not SIGKILL aliases."""
import base64
import json
import re
import threading
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import ROOT, PACKAGE, Server, Proxy, adb, call, pid, await_condition


def main():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    api=int(adb('shell','getprop','ro.build.version.sdk'))
    suite=ET.Element('testsuite',name='SYN443 fatal native owner recovery')
    out=ROOT/'app/build/outputs/androidTest-results/external/TEST-vpn-fatal.xml'
    proxy=Server(('127.0.0.1',0),Proxy);port=str(proxy.server_address[1])
    threading.Thread(target=proxy.serve_forever,daemon=True).start()
    case=None
    def new_case(name):
        return ET.SubElement(suite,'testcase',classname='io.syn443.android.FatalOwnerTest',name=name)
    def stop():
        call('disconnect');await_condition(lambda:not pid(':engine') and not call('status')['engineActive'],30)
    def prepare():
        stop();call('policy-test-reset');call('test-reset')
        adb('shell','am','start','-W','-n',PACKAGE+'/.MainActivity')
        config={'outbounds':[{'type':'http','tag':'test-proxy','server':'127.0.0.1','server_port':int(port)}],'route':{'final':'test-proxy'}}
        call('import',base64.b64encode(json.dumps(config).encode()).decode());call('test-health','synthetic-http')
        progress=proxy.progress;call('connect')
        await_condition(lambda:call('status')['phase']=='Online' and pid(':engine') and proxy.progress>progress)
        # Exercise a background VPN, as on the physical phone. Foreground crash
        # dialogs may hold Android's synchronous fatal-error handler for user input.
        adb('shell','input','keyevent','KEYCODE_HOME')
    def prove_exit(old,kind):
        if api>=30:
            expected=('java_crash',) if kind=='java' else ('native_crash','signal')
            await_condition(lambda:any(x['kind'] in expected and (kind=='java' or x.get('status')==6) for x in call('engine-exits',old)['exits']),30)
        logs=adb('logcat','-b','all','-d','--pid='+old,'-t','2000',timeout=20)
        assert len(logs)<=2*1024*1024
        marker=b'SYN443 synthetic Java failure' if kind=='java' else b'SYN443 synthetic native failure'
        assert marker in logs,'The actual uncaught fault marker was not observed'
        if api<30:
            # API29 has no ApplicationExitInfo. Match the crashed owner in OS crash output.
            if kind=='java':assert b'FATAL EXCEPTION' in logs
            else:
                crash=adb('logcat','-b','crash','-d','-t','2000',timeout=20)
                assert re.search(rb'pid:\s*'+old.encode()+rb'\b',crash) and b'SIGABRT' in crash
    try:
        adb('reverse','tcp:'+port,'tcp:'+port)
        stop()
        case=new_case('fatalCommandsCannotStartAnOffNativeOwner')
        before=call('status')
        for method in ('fault-java','fault-native'):
            try:call(method)
            except AssertionError:pass
            else:raise AssertionError('Fatal command accepted while Off')
        assert not pid(':engine') and call('status')['generation']==before['generation']
        print(case.get('name')+': passed',flush=True)
        for kind in ('java','native'):
            case=new_case('uncaught'+kind.title()+'FaultRecoversRealTunAndRetainsIntent')
            prepare();before=call('status');old=pid(':engine');assert old
            progress=proxy.progress;call('fault-'+kind)
            await_condition(lambda:pid(':engine')!=old,50);prove_exit(old,kind)
            await_condition(lambda:call('status')['phase']=='Online' and pid(':engine') not in ('',old) and proxy.progress>progress,150)
            current=call('status');assert current['generation']==before['generation'] and current['desiredOn']
            assert len(current['heavyWallMs'])==len(before.get('heavyWallMs',[]))+1
            assert len(current['heavyWallMs'])<=3
            print(case.get('name')+': passed',flush=True)
        case=new_case('fatalCrashSeriesPreservesRestartBudgetAndStopFencesLateRecovery')
        prepare();generation=call('status')['generation']
        initial=len(call('status').get('heavyWallMs',[]));assert initial in (0,1)
        # Cold launch may be free; the policy limits heavy RESTARTS, not all owners.
        for expected in range(initial+1,4):
            old=pid(':engine');assert old;progress=proxy.progress;call('fault-java')
            await_condition(lambda:pid(':engine')!=old,50);prove_exit(old,'java')
            await_condition(lambda:call('status')['phase']=='Online' and pid(':engine') not in ('',old) and proxy.progress>progress,150)
            assert len(call('status')['heavyWallMs'])==expected
        old=pid(':engine');assert old;call('fault-java')
        await_condition(lambda:pid(':engine')!=old,50);prove_exit(old,'java')
        await_condition(lambda:not pid(':engine') and len(call('status')['heavyWallMs'])==3 and call('status')['nextWallMs']>=min(call('status')['heavyWallMs'])+600_000,30)
        before=call('status');assert before['generation']==generation and before['desiredOn']
        old_controller=pid(':controller');call('fault-controller')
        await_condition(lambda:pid(':controller')!=old_controller,20)
        await_condition(lambda:len(call('status')['heavyWallMs'])==3 and not pid(':engine'),20)
        stop();stopped=call('status');time.sleep(8)
        assert not pid(':engine') and not call('status')['desiredOn'] and call('status')['generation']==stopped['generation']
        assert call('status')['heavyWallMs']==stopped['heavyWallMs']
        print(case.get('name')+': passed',flush=True)
    except Exception as error:
        if case is not None:ET.SubElement(case,'failure',message=type(error).__name__).text=str(error)
        raise
    finally:
        try:stop();call('test-health','production-https')
        finally:
            adb('reverse','--remove','tcp:'+port);proxy.shutdown();proxy.server_close()
            out.parent.mkdir(parents=True,exist_ok=True);ET.ElementTree(suite).write(out,encoding='utf-8',xml_declaration=True)


if __name__=='__main__':main()
