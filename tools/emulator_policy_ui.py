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
        # sys.boot_completed can precede a responsive Keyguard. Repeating only
        # wake/swipe before any digits are entered does not replay a PIN attempt.
        adb('shell','input','keyevent','KEYCODE_WAKEUP')
        adb('shell','input','swipe',str(width//2),str(height*9//10),str(width//2),str(height//3),'300')
        time.sleep(1)
    raise AssertionError('Disposable emulator PIN bouncer did not become ready')


def profile_settings(root):
    """Only the owned Settings row, never a SystemUI label or another VPN gear."""
    parents={c:p for p in root.iter() for c in p}
    def bounds(node):
        values=re.findall(r'\d+',node.get('bounds',''))
        return tuple(map(int,values)) if len(values)==4 else None
    for label in root.iter('node'):
        if label.get('package')!='com.android.settings' or label.get('text')!='SYN443':continue
        label_bounds=bounds(label)
        if label_bounds is None:continue
        container=label
        for _ in range(4):
            container=parents.get(container,container)
            for gear in container.iter('node'):
                if gear.get('package')!='com.android.settings':continue
                description=gear.get('content-desc','')
                if description and description!='Settings for SYN443':continue
                if description!='Settings for SYN443' and not gear.get('resource-id','').endswith('/settings_button'):continue
                gear_bounds=bounds(gear)
                if gear_bounds is not None and max(label_bounds[1],gear_bounds[1])<min(label_bounds[3],gear_bounds[3]):return gear
    return None


def open_policy():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    # Reboots can leave a nonsecure keyguard or a previously restored Settings
    # fragment. Wake/swipe and start the VPN task afresh; never enter a PIN here.
    adb('shell','input','keyevent','KEYCODE_WAKEUP')
    dimensions=re.findall(r'(\d+)x(\d+)',adb('shell','wm','size').decode())
    assert dimensions,'Disposable emulator dimensions unavailable'
    width,height=map(int,dimensions[-1])
    adb('shell','input','swipe',str(width//2),str(height*9//10),str(width//2),str(height//3),'300')
    adb('shell','am','start','-W','-a','android.settings.VPN_SETTINGS','-f','0x10008000')
    end=time.monotonic()+20
    root=None
    while time.monotonic()<end:
        root=tree()
        if pin_keys(root):raise AssertionError('Protected emulator keyguard unexpectedly active')
        gear=profile_settings(root)
        if gear is not None:tap(gear);return
        time.sleep(1)
    # Structural data only: no arbitrary UI text, identifiers or auth content.
    nodes=[] if root is None else list(root.iter('node'))
    packages=sorted({n.get('package','') for n in nodes})[:8]
    resources=sorted({n.get('resource-id','') for n in nodes if n.get('package') in ('com.android.settings','com.android.systemui')})[:32]
    print('Owned VPN Settings navigation unavailable: '+repr({'packages':packages,'resources':resources,'ownedLabel':any(n.get('package')=='com.android.settings' and n.get('text')=='SYN443' for n in nodes)}),flush=True)
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
