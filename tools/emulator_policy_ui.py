"""Ordinary Android Settings controls, for disposable emulator lifecycle tests."""
import re
import shlex
import subprocess
import time
import xml.etree.ElementTree as ET
from run_vpn_process_faults import adb


def tree():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    path='/data/local/tmp/syn443-os-policy.xml'
    deadline=time.monotonic()+25
    last=None
    def command(*args,maximum=15):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise subprocess.TimeoutExpired('bounded emulator UI observation',25)
        return adb(*args,timeout=min(maximum,remaining))
    for attempt in range(3):
        try:
            # uiautomator may exit0 before Keyguard has a root, without writing
            # a file. Never accept a leftover hierarchy from an earlier screen.
            command('shell','rm','-f',path,maximum=3)
            command('shell','uiautomator','dump',path)
            root=ET.fromstring(command('shell','cat',path,maximum=3))
            if root.tag!='hierarchy':raise ET.ParseError('Unexpected emulator hierarchy root')
            return root
        except (subprocess.CalledProcessError,subprocess.TimeoutExpired,ET.ParseError) as e:
            last=e
        finally:
            try:adb('shell','rm','-f',path,timeout=2)
            except (subprocess.CalledProcessError,subprocess.TimeoutExpired):pass
        remaining=deadline-time.monotonic()
        if attempt==2 or remaining<=0:break
        time.sleep(min(.25,remaining))
    raise AssertionError('Disposable emulator UI hierarchy did not become ready within its observation budget') from last


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
        container=label
        for _ in range(4):
            container=parents.get(container,container)
            gears=[n for n in container.iter('node') if n.get('package')=='com.android.settings' and
                   (n.get('resource-id','').endswith('/settings_button') or n.get('content-desc')=='Settings for SYN443')]
            titles=[n for n in container.iter('node') if n.get('package')=='com.android.settings' and n.get('resource-id')=='android:id/title']
            # A two-line preference can place its title above the gear. Match
            # their unique owned row, not overlapping text/icon rectangles or
            # an English-only description. Never ascend into multiple VPN rows.
            if len(gears)!=1 or len(titles)>1 or titles and titles[0] is not label:continue
            for gear in gears:
                description=gear.get('content-desc','')
                if description.startswith('Settings for ') and description!='Settings for SYN443':continue
                row_bounds=bounds(container);label_bounds=bounds(label)
                gear_bounds=bounds(gear)
                if row_bounds is None or label_bounds is None or gear_bounds is None:continue
                if all(row_bounds[0]<=b[0]<b[2]<=row_bounds[2] and row_bounds[1]<=b[1]<b[3]<=row_bounds[3] for b in (label_bounds,gear_bounds)):return gear
    return None


def settings_component(raw):
    """Accept only platform-resolved Settings components, never a chooser app."""
    if len(raw)>8192:return None
    values=[]
    for line in raw.decode('utf-8',errors='strict').splitlines():
        line=line.strip()
        if not re.fullmatch(r'[A-Za-z0-9_.]+/[A-Za-z0-9_.$]+',line):continue
        package,activity=line.split('/',1)
        if package!='com.android.settings' or not (activity.startswith('.') or activity.startswith('com.android.settings.')):return None
        values.append(line)
    values=sorted(set(values))
    if len(values)==1:return values[0]
    vpn=[v for v in values if re.search(r'[.$]VpnSettingsActivity$',v)]
    return vpn[0] if len(vpn)==1 else None


def focused_settings_anr(windows):
    """The platform attaches the ANR process name to its focused window."""
    if len(windows)>1_048_576:return False
    focus=re.findall(rb'(?m)^\s*mCurrentFocus=([^\r\n]+)',windows)
    return len(focus)==1 and re.fullmatch(
        rb'Window\{[^}\r\n]* Application Not Responding: com\.android\.settings\}',focus[0].strip(),
    ) is not None


def classified_focus_snapshot(windows):
    """Diagnostic categories only; never return window titles or process data."""
    if not isinstance(windows,bytes) or len(windows)>1_048_576:
        return {'focusCount':None,'category':'unrecognized'}
    focus=re.findall(rb'(?m)^\s*mCurrentFocus=([^\r\n]+)',windows)
    count=len(focus)
    if count>1:category='ambiguous'
    elif count==0:category='unrecognized'
    elif focus[0].strip()==b'null':category='null'
    elif focused_settings_anr(windows):category='settings_anr'
    elif re.fullmatch(rb'Window\{[^}\r\n]* Application Not Responding: io\.syn443\.android(?::(?:controller|engine))?\}',focus[0].strip()):
        category='app_anr'
    elif re.fullmatch(rb'Window\{[^}\r\n]* Application Not Responding: [^}\r\n]+\}',focus[0].strip()):
        category='foreign_anr'
    else:category='unrecognized'
    return {'focusCount':count,'category':category}


def _anr_focus(windows):
    if not isinstance(windows,bytes) or len(windows)>1_048_576:return None
    focus=re.findall(rb'(?m)^\s*mCurrentFocus=([^\r\n]+)',windows)
    if len(focus)!=1:return None
    value=focus[0].strip()
    match=re.fullmatch(rb'Window\{[0-9a-f]+ u([0-9]{1,5}) Application Not Responding: ([A-Za-z0-9_.:]{1,160})\}',value)
    return (value,int(match[1]),match[2]) if match else None


def correlated_anr_owner(before,after,events,processes,started,finished):
    """Return fixed categories only, never a title, process, PID, UID or reason.

    am_anr's first field is a user ID, NOT a UID. Bind its PID/process to
    am_proc_start's UID and the current, still-not-responding ProcessRecord.
    Historical lastanr activity snapshots alone cannot establish that owner.
    Unknown formats, replaced focus/processes and multiple recent ANRs fail
    closed. This diagnostic never authorizes a UI action or recovery.
    """
    unknown={'category':'unknown','correlated':False}
    focus=_anr_focus(before)
    if focus is None or focus!=_anr_focus(after):return unknown
    if any(not isinstance(raw,bytes) or len(raw)>1_048_576 for raw in (events,processes)):return unknown
    if type(started) is not int or type(finished) is not int or not 0<=finished-started<=10:return unknown
    # Device wall time has second precision; allow its current second, not
    # another clock's time. A recent event must be at most two minutes old.
    oldest=(finished-120)*1_000_000;newest=(finished+1)*1_000_000
    parsed=[]
    for line in events.splitlines():
        if len(line)>16_384:return unknown
        if not re.search(rb'\bam_(?:anr|proc_start)\s*:',line):continue
        match=re.fullmatch(rb'([0-9]{9,12})\.([0-9]{3,6})\s+[0-9]+\s+[0-9]+\s+I\s+(am_anr|am_proc_start)\s*:\s*\[([^\r\n]*)\]',line.strip())
        if match is None:return unknown
        stamp=int(match[1])*1_000_000+int(match[2].ljust(6,b'0'))
        fields=match[4].split(b',',4)
        if len(fields)!=5 or not all(re.fullmatch(rb'[0-9]{1,10}',field) for field in fields[:2]):return unknown
        user,pid=map(int,fields[:2])
        if user>9999 or not 0<pid<=2_147_483_647:return unknown
        if match[3]==b'am_anr':
            if not re.fullmatch(rb'[A-Za-z0-9_.:]{1,160}',fields[2]) or not re.fullmatch(rb'[0-9]{1,10}',fields[3]):return unknown
            parsed.append((stamp,'anr',user,pid,fields[2],None))
        else:
            if not re.fullmatch(rb'[0-9]{1,10}',fields[2]) or not re.fullmatch(rb'[A-Za-z0-9_.:]{1,160}',fields[3]):return unknown
            uid=int(fields[2])
            if uid>2_147_483_647 or uid//100_000!=user:return unknown
            parsed.append((stamp,'start',user,pid,fields[3],uid))
        if len(parsed)>256:return unknown
    recent=[row for row in parsed if row[1]=='anr' and oldest<=row[0]<newest]
    if len(recent)!=1:return unknown
    event=recent[0]
    if (event[2],event[4])!=focus[1:]:return unknown
    starts=[row for row in parsed if row[1]=='start' and row[3]==event[3]]
    if len(starts)!=1:return unknown
    source=starts[0]
    if source[0]>=event[0] or source[2:5]!=event[2:5]:return unknown
    # Dump format from ProcessList/ProcessRecord/ProcessErrorStateRecord. A
    # package prefix, a previous process or an isolated UID is not ownership.
    if processes.count(b'ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)')!=1:return unknown
    headers=list(re.finditer(rb'(?m)^\s*\*(?:APP|PERS)\* UID ([0-9]{1,10}) ProcessRecord\{[0-9a-f]+ ([0-9]{1,10}):([A-Za-z0-9_.:]{1,160})/([A-Za-z0-9]{1,32})\}\s*$',processes))
    if not headers or len(headers)!=len(re.findall(rb'(?m)^\s*\*(?:APP|PERS)\* UID ',processes)):return unknown
    if len(re.findall(rb'\bmNotResponding=true\b',processes))!=1:return unknown
    candidates=[]
    for index,header in enumerate(headers):
        block=processes[header.end():headers[index+1].start() if index+1<len(headers) else len(processes)]
        flags=re.findall(rb'(?m)^\s*mCrashing=false [^\r\n]{0,2048}\bmNotResponding=true \[com\.android\.server\.am\.AppNotRespondingDialog@[0-9a-f]+\] bad=false(?: [^\r\n]*)?$',block)
        if len(flags)!=1:continue
        uid,pid=int(header[1]),int(header[2]);name=header[3]
        user=uid//100_000;app_id=uid%100_000
        descriptor=(str(uid).encode() if uid<10_000 else f'u{user}{"a" if app_id>=10_000 else "s"}{app_id-10_000 if app_id>=10_000 else app_id}'.encode())
        if header[4]!=descriptor:continue
        identities=re.findall(rb'(?m)^\s*user #([0-9]{1,5}) uid=([0-9]{1,10}) gids=\{[^\r\n]*\}\s*$',block)
        pids=re.findall(rb'(?m)^\s*pid=([0-9]{1,10})(?: starting=(?:true|false))?\s*$',block)
        if identities!=[(str(user).encode(),str(uid).encode())] or pids!=[str(pid).encode()]:continue
        if (user,pid,name,uid)==(event[2],event[3],event[4],source[5]):candidates.append(name)
    if len(candidates)!=1:return unknown
    categories={
        b'com.android.settings':'settings',b'com.android.systemui':'system_ui',
        b'com.android.launcher3':'launcher',b'com.google.android.apps.nexuslauncher':'launcher',
        b'com.android.permissioncontroller':'permission_controller',b'com.google.android.permissioncontroller':'permission_controller',
        b'com.google.android.gms':'google_services',b'com.android.vending':'play_store',
        b'io.syn443.android':'syn443_app',b'io.syn443.android:controller':'syn443_controller',b'io.syn443.android:engine':'syn443_engine',
    }
    category=categories.get(candidates[0])
    return {'category':category,'correlated':True} if category is not None else unknown


def anr_owner_diagnostic():
    """Read-only, disposable-emulator failure diagnostic with an eight-second budget."""
    unknown={'category':'unknown','correlated':False}
    deadline=time.monotonic()+8
    def observe(*args):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise subprocess.TimeoutExpired('bounded ANR owner observation',8)
        raw=adb(*args,timeout=min(2,remaining))
        if not isinstance(raw,bytes) or len(raw)>1_048_576:raise ValueError('Unusable diagnostic observation')
        return raw
    try:
        if observe('shell','getprop','ro.hardware').strip() not in (b'ranchu',b'goldfish'):return unknown
        started=observe('shell','date','+%s').strip()
        if not re.fullmatch(rb'[0-9]{9,12}',started):return unknown
        before=observe('shell','dumpsys','window','displays')
        if _anr_focus(before) is None:return unknown
        # All command arguments are constants. Neither titles nor log fields
        # are interpolated into a shell command, package filter or file path.
        events=observe('shell','logcat','-d','-b','events','-v','epoch','-t','256','am_anr:I','am_proc_start:I',"'*:S'")
        processes=observe('shell','dumpsys','activity','-a','processes')
        after=observe('shell','dumpsys','window','displays')
        finished=observe('shell','date','+%s').strip()
        if not re.fullmatch(rb'[0-9]{9,12}',finished):return unknown
        return correlated_anr_owner(before,after,events,processes,int(started),int(finished))
    except (OSError,subprocess.SubprocessError,ValueError,UnicodeError):
        return unknown


def open_policy():
    assert adb('shell','getprop','ro.hardware').decode().strip() in ('ranchu','goldfish')
    # Reboots can leave a nonsecure keyguard or a previously restored Settings
    # fragment. Wake/swipe and start the VPN task afresh; never enter a PIN here.
    adb('shell','input','keyevent','KEYCODE_WAKEUP')
    dimensions=re.findall(r'(\d+)x(\d+)',adb('shell','wm','size').decode())
    assert dimensions,'Disposable emulator dimensions unavailable'
    width,height=map(int,dimensions[-1])
    adb('shell','input','swipe',str(width//2),str(height*9//10),str(width//2),str(height//3),'300')
    # Resolve the actual platform component. A package-restricted implicit
    # intent may still leave a framework window after a reboot. Launch the
    # verified Settings component afresh, without clicking framework dialogs.
    args=('shell','cmd','package')
    component=settings_component(adb(*args,'resolve-activity','--brief','-a','android.settings.VPN_SETTINGS','-p','com.android.settings'))
    if component is None:
        component=settings_component(adb(*args,'query-activities','--brief','-a','android.settings.VPN_SETTINGS','-p','com.android.settings'))
    assert component is not None,'Platform did not resolve an owned VPN Settings component'
    launch=('shell','am','start','-S','-W','-n',shlex.quote(component),'-f','0x10008000')
    adb(*launch)
    end=time.monotonic()+20
    root=None
    relaunched=False
    last_settings_anr=None
    last_focus_snapshot={'focusCount':None,'category':'unrecognized'}
    while time.monotonic()<end:
        root=tree()
        if pin_keys(root):raise AssertionError('Protected emulator keyguard unexpectedly active')
        gear=profile_settings(root)
        if gear is not None:tap(gear);return
        # Never press a generic error dialog. Restart only the already resolved
        # Settings activity once, after confirming that its own ANR has focus.
        if not relaunched and any(n.get('package')=='android' and n.get('resource-id')=='android:id/aerr_close'
                                   for n in root.iter('node')):
            # DisplayContent owns current focus on modern Android. The windows
            # subcommand lists windows but does not include that owner field.
            windows=adb('shell','dumpsys','window','displays',timeout=5)
            last_settings_anr=focused_settings_anr(windows)
            last_focus_snapshot=classified_focus_snapshot(windows)
            if last_settings_anr:
                relaunched=True
                print('Owned Settings ANR: restarting the VPN settings activity once',flush=True)
                adb(*launch)
                end=time.monotonic()+20
                continue
        time.sleep(1)
    # Structural data only: no arbitrary UI text, identifiers or auth content.
    nodes=[] if root is None else list(root.iter('node'))
    packages=sorted({n.get('package','') for n in nodes})[:8]
    resources=sorted({n.get('resource-id','') for n in nodes if n.get('package') in ('android','com.android.settings','com.android.systemui')})[:32]
    owned=[{'id':n.get('resource-id',''),'bounds':n.get('bounds','')} for n in nodes if n.get('package')=='com.android.settings' and n.get('text')=='SYN443']
    gears=[{'bounds':n.get('bounds',''),'description':('expected' if n.get('content-desc')=='Settings for SYN443' else 'present' if n.get('content-desc') else 'empty')} for n in nodes if n.get('package')=='com.android.settings' and n.get('resource-id','').endswith('/settings_button')]
    owner=anr_owner_diagnostic() if any(n.get('package')=='android' and n.get('resource-id')=='android:id/aerr_close' for n in nodes) else {'category':'unknown','correlated':False}
    print('Owned VPN Settings navigation unavailable: '+repr({'packages':packages,'resources':resources,'owned':owned,'gears':gears,'focusedSettingsANR':last_settings_anr,'focusSnapshot':last_focus_snapshot,'anrOwner':owner}),flush=True)
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
