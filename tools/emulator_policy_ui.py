"""Ordinary Android Settings controls, for disposable emulator lifecycle tests."""
import re
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import adb


def tree():
    adb('shell','uiautomator','dump','/data/local/tmp/syn443-os-policy.xml',timeout=20)
    return ET.fromstring(adb('shell','cat','/data/local/tmp/syn443-os-policy.xml'))


def tap(node):
    x1,y1,x2,y2=map(int,re.findall(r'\d+',node.get('bounds','')))
    adb('shell','input','tap',str((x1+x2)//2),str((y1+y2)//2))


def pin_keys(root):
    """Only the disposable emulator's SystemUI PIN bouncer, never another app."""
    parents={c:p for p in root.iter() for c in p};keys={}
    for node in root.iter('node'):
        if node.get('package')!='com.android.systemui':continue
        match=re.search(r'/key([0-9])$',node.get('resource-id',''))
        digit=match[1] if match else node.get('text','')
        if digit not in tuple('0123456789'):continue
        target=node
        for _ in range(4):
            if target.get('clickable')=='true':break
            target=parents.get(target,target)
        if target.get('package')=='com.android.systemui' and target.get('clickable')=='true':keys[digit]=target
    return keys if set('123456789')<=set(keys) else {}


def unlock_test_pin():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    adb('shell','input','keyevent','KEYCODE_WAKEUP')
    time.sleep(1)
    width,height=map(int,re.findall(r'(\d+)x(\d+)',adb('shell','wm','size').decode())[-1])
    adb('shell','input','swipe',str(width//2),str(height*9//10),str(width//2),str(height//3),'300')
    end=time.monotonic()+20
    while time.monotonic()<end:
        root=tree();keys=pin_keys(root)
        if keys:
            for digit in '2468':tap(keys[digit])
            enter=next((n for n in root.iter('node') if n.get('package')=='com.android.systemui' and n.get('resource-id','').endswith('/key_enter')),None)
            if enter is not None:tap(enter)
            else:adb('shell','input','keyevent','KEYCODE_ENTER')
            return
        time.sleep(1)
    raise AssertionError('Disposable emulator PIN bouncer did not become ready')


def open_policy():
    adb('shell','am','start','-a','android.settings.VPN_SETTINGS')
    end=time.monotonic()+20
    while time.monotonic()<end:
        root=tree();parents={c:p for p in root.iter() for c in p}
        for label in root.iter('node'):
            if label.get('text')!='SYN443':continue
            container=label
            for _ in range(4):
                container=parents.get(container,container)
                gear=next((n for n in container.iter('node') if 'settings_button' in n.get('resource-id','') or n.get('content-desc','').startswith('Settings for')),None)
                if gear is not None:tap(gear);return
        time.sleep(1)
    raise AssertionError('Owned VPN settings entry unavailable')


def toggle(text,enabled):
    end=time.monotonic()+20
    while time.monotonic()<end:
        root=tree();parents={c:p for p in root.iter() for c in p};clicked=False
        for label in root.iter('node'):
            if label.get('text')!=text:continue
            container=label
            for _ in range(4):
                checks=[n for n in container.iter('node') if n.get('checkable')=='true']
                if checks:
                    check=checks[0]
                    if (check.get('checked')=='true')==enabled:return
                    tap(check);clicked=True;break
                container=parents.get(container,container)
            if clicked:break
        if not clicked:
            positive=next((n for n in root.iter('node') if n.get('resource-id')=='android:id/button1'),None)
            if positive is not None:tap(positive)
        time.sleep(1)
    raise AssertionError('OS VPN preference did not reach requested value')
