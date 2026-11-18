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


_EVIDENCE_STAGES=frozenset(('input','hardware','clock','focus','events','process_start','process','owner','complete'))
_EVIDENCE_REASONS=frozenset(('not_observed','unavailable','oversized','malformed','missing','ambiguous','changed',
                           'stale_or_future','identity_mismatch','unmapped_owner','timeout','transport_error',
                           'not_emulator','known_owner'))
_EVIDENCE_COUNTS=('focus_before','focus_after','recent_anr','process_start','active_anr','matching_process')


def _owner_evidence(evidence,stage,reason,counts=None,correlated=False):
    """Owned, fixed diagnostic data only. Never navigation/recovery authority."""
    if type(evidence) is not dict:return
    stage=stage if stage in _EVIDENCE_STAGES else 'input'
    reason=reason if reason in _EVIDENCE_REASONS else 'unavailable'
    source=counts if type(counts) is dict else {}
    bounded={key:min(2,max(0,source.get(key))) if type(source.get(key)) is int else None for key in _EVIDENCE_COUNTS}
    evidence.clear()
    evidence.update({'stage':stage,'reason':reason,'trust':'correlated' if correlated is True else 'unverified','counts':bounded})


def launch_status(raw):
    """Classify bytes already returned by am start -W, without echoing them."""
    if not isinstance(raw,bytes):return {'kind':'unavailable'}
    if len(raw)>16_384:return {'kind':'oversized'}
    try:text=raw.decode('utf-8',errors='strict')
    except UnicodeError:return {'kind':'malformed'}
    statuses=re.findall(r'(?m)^Status:[ \t]*([^\r\n]*)\r?$',text)
    errors=re.findall(r'(?m)^(?:Error(?: type [0-9]+)?:|Exception occurred while executing)',text)
    if len(statuses)>1 or statuses and errors:return {'kind':'ambiguous'}
    if errors:return {'kind':'error'}
    if not statuses:return {'kind':'unrecognized'}
    value=statuses[0].strip()
    return {'kind':value if value in ('ok','timeout') else 'unrecognized'}


def correlated_anr_owner(before,after,events,processes,started,finished,*,evidence=None):
    """Return fixed categories only, never a title, process, PID, UID or reason.

    am_anr's first field is a user ID, NOT a UID. Bind its PID/process to
    am_proc_start's UID and the current, still-not-responding ProcessRecord.
    Historical lastanr activity snapshots alone cannot establish that owner.
    Unknown formats, replaced focus/processes and multiple recent ANRs fail
    closed. This diagnostic never authorizes a UI action or recovery.
    """
    unknown={'category':'unknown','correlated':False}
    counts={key:None for key in _EVIDENCE_COUNTS}
    def stop(stage,reason):
        _owner_evidence(evidence,stage,reason,counts)
        return unknown
    for raw in (before,after,events,processes):
        if not isinstance(raw,bytes):return stop('input','unavailable')
        if len(raw)>1_048_576:return stop('input','oversized')
    counts['focus_before']=min(2,len(re.findall(rb'(?m)^\s*mCurrentFocus=([^\r\n]+)',before)))
    counts['focus_after']=min(2,len(re.findall(rb'(?m)^\s*mCurrentFocus=([^\r\n]+)',after)))
    focus=_anr_focus(before)
    if counts['focus_before']>1 or counts['focus_after']>1:return stop('focus','ambiguous')
    if counts['focus_before']==0 or counts['focus_after']==0:return stop('focus','missing')
    if focus is None or _anr_focus(after) is None:return stop('focus','malformed')
    if focus!=_anr_focus(after):return stop('focus','changed')
    if type(started) is not int or type(finished) is not int or not 0<=finished-started<=10:return stop('clock','malformed')
    # Device wall time has second precision; allow its current second, not
    # another clock's time. A recent event must be at most two minutes old.
    oldest=(finished-120)*1_000_000;newest=(finished+1)*1_000_000
    parsed=[]
    for line in events.splitlines():
        if len(line)>16_384:return stop('events','oversized')
        if not re.search(rb'\bam_(?:anr|proc_start)\s*:',line):continue
        match=re.fullmatch(rb'([0-9]{9,12})\.([0-9]{3,6})\s+[0-9]+\s+[0-9]+\s+I\s+(am_anr|am_proc_start)\s*:\s*\[([^\r\n]*)\]',line.strip())
        if match is None:return stop('events','malformed')
        stamp=int(match[1])*1_000_000+int(match[2].ljust(6,b'0'))
        fields=match[4].split(b',',4)
        if len(fields)!=5 or not all(re.fullmatch(rb'[0-9]{1,10}',field) for field in fields[:2]):return stop('events','malformed')
        user,pid=map(int,fields[:2])
        if user>9999 or not 0<pid<=2_147_483_647:return stop('events','malformed')
        if match[3]==b'am_anr':
            if not re.fullmatch(rb'[A-Za-z0-9_.:]{1,160}',fields[2]) or not re.fullmatch(rb'[0-9]{1,10}',fields[3]):return stop('events','malformed')
            parsed.append((stamp,'anr',user,pid,fields[2],None))
        else:
            if not re.fullmatch(rb'[0-9]{1,10}',fields[2]) or not re.fullmatch(rb'[A-Za-z0-9_.:]{1,160}',fields[3]):return stop('events','malformed')
            uid=int(fields[2])
            if uid>2_147_483_647 or uid//100_000!=user:return stop('process_start','identity_mismatch')
            parsed.append((stamp,'start',user,pid,fields[3],uid))
        if len(parsed)>256:return stop('events','oversized')
    recent=[row for row in parsed if row[1]=='anr' and oldest<=row[0]<newest]
    counts['recent_anr']=min(2,len(recent))
    if len(recent)!=1:return stop('events','ambiguous' if len(recent)>1 else 'stale_or_future' if any(row[1]=='anr' for row in parsed) else 'missing')
    event=recent[0]
    if (event[2],event[4])!=focus[1:]:return stop('focus','identity_mismatch')
    starts=[row for row in parsed if row[1]=='start' and row[3]==event[3]]
    counts['process_start']=min(2,len(starts))
    if len(starts)!=1:return stop('process_start','ambiguous' if len(starts)>1 else 'missing')
    source=starts[0]
    if source[0]>=event[0] or source[2:5]!=event[2:5]:return stop('process_start','identity_mismatch')
    # Dump format from ProcessList/ProcessRecord/ProcessErrorStateRecord. A
    # package prefix, a previous process or an isolated UID is not ownership.
    if processes.count(b'ACTIVITY MANAGER RUNNING PROCESSES (dumpsys activity processes)')!=1:return stop('process','missing')
    headers=list(re.finditer(rb'(?m)^\s*\*(?:APP|PERS)\* UID ([0-9]{1,10}) ProcessRecord\{[0-9a-f]+ ([0-9]{1,10}):([A-Za-z0-9_.:]{1,160})/([A-Za-z0-9]{1,32})\}\s*$',processes))
    if not headers:return stop('process','missing')
    if len(headers)!=len(re.findall(rb'(?m)^\s*\*(?:APP|PERS)\* UID ',processes)):return stop('process','malformed')
    counts['active_anr']=min(2,len(re.findall(rb'\bmNotResponding=true\b',processes)))
    if len(re.findall(rb'\bmNotResponding=true\b',processes))!=1:return stop('process','ambiguous' if counts['active_anr']>1 else 'missing')
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
    counts['matching_process']=min(2,len(candidates))
    if len(candidates)!=1:return stop('process','identity_mismatch' if len(candidates)==0 else 'ambiguous')
    categories={
        b'com.android.settings':'settings',b'com.android.systemui':'system_ui',
        b'com.android.launcher3':'launcher',b'com.google.android.apps.nexuslauncher':'launcher',
        b'com.android.permissioncontroller':'permission_controller',b'com.google.android.permissioncontroller':'permission_controller',
        b'com.google.android.gms':'google_services',b'com.android.vending':'play_store',
        b'io.syn443.android':'syn443_app',b'io.syn443.android:controller':'syn443_controller',b'io.syn443.android:engine':'syn443_engine',
    }
    category=categories.get(candidates[0])
    if category is None:return stop('owner','unmapped_owner')
    _owner_evidence(evidence,'complete','known_owner',counts,True)
    return {'category':category,'correlated':True}


def anr_owner_diagnostic(*,evidence=None):
    """Read-only, disposable-emulator failure diagnostic with an eight-second budget."""
    unknown={'category':'unknown','correlated':False}
    stage='hardware'
    _owner_evidence(evidence,'input','not_observed')
    deadline=time.monotonic()+8
    def observe(*args):
        remaining=deadline-time.monotonic()
        if remaining<=0:raise subprocess.TimeoutExpired('bounded ANR owner observation',8)
        raw=adb(*args,timeout=min(2,remaining))
        if not isinstance(raw,bytes):raise ValueError('unavailable')
        if len(raw)>1_048_576:raise ValueError('oversized')
        return raw
    try:
        if observe('shell','getprop','ro.hardware').strip() not in (b'ranchu',b'goldfish'):
            _owner_evidence(evidence,stage,'not_emulator');return unknown
        stage='clock'
        started=observe('shell','date','+%s').strip()
        if not re.fullmatch(rb'[0-9]{9,12}',started):
            _owner_evidence(evidence,stage,'malformed');return unknown
        stage='focus'
        before=observe('shell','dumpsys','window','displays')
        if _anr_focus(before) is None:
            count=min(2,len(re.findall(rb'(?m)^\s*mCurrentFocus=([^\r\n]+)',before)))
            _owner_evidence(evidence,stage,'ambiguous' if count>1 else 'malformed' if count else 'missing',{'focus_before':count});return unknown
        # All command arguments are constants. Neither titles nor log fields
        # are interpolated into a shell command, package filter or file path.
        stage='events'
        # logd applies the raw tail before logcat applies the tag filter.
        # Reboot traffic can crowd out a recent ANR or its process start.
        # Read a larger bounded tail only on failure. The existing byte,
        # parsed-row, clock, and eight-second limits still govern evidence.
        events=observe('shell','logcat','-d','-b','events','-v','epoch','-t','2048','am_anr:I','am_proc_start:I',"'*:S'")
        stage='process'
        processes=observe('shell','dumpsys','activity','-a','processes')
        stage='focus'
        after=observe('shell','dumpsys','window','displays')
        stage='clock'
        finished=observe('shell','date','+%s').strip()
        if not re.fullmatch(rb'[0-9]{9,12}',finished):
            _owner_evidence(evidence,stage,'malformed');return unknown
        return correlated_anr_owner(before,after,events,processes,int(started),int(finished),evidence=evidence)
    except subprocess.TimeoutExpired:
        _owner_evidence(evidence,stage,'timeout')
        return unknown
    except (OSError,subprocess.SubprocessError):
        _owner_evidence(evidence,stage,'transport_error')
        return unknown
    except (ValueError,UnicodeError) as error:
        _owner_evidence(evidence,stage,str(error) if str(error) in ('unavailable','oversized') else 'malformed')
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
    launch_observations=[launch_status(adb(*launch))]
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
                launch_observations.append(launch_status(adb(*launch)))
                end=time.monotonic()+20
                continue
        time.sleep(1)
    # Structural data only: no arbitrary UI text, identifiers or auth content.
    nodes=[] if root is None else list(root.iter('node'))
    packages=sorted({n.get('package','') for n in nodes})[:8]
    resources=sorted({n.get('resource-id','') for n in nodes if n.get('package') in ('android','com.android.settings','com.android.systemui')})[:32]
    owned=[{'id':n.get('resource-id',''),'bounds':n.get('bounds','')} for n in nodes if n.get('package')=='com.android.settings' and n.get('text')=='SYN443']
    gears=[{'bounds':n.get('bounds',''),'description':('expected' if n.get('content-desc')=='Settings for SYN443' else 'present' if n.get('content-desc') else 'empty')} for n in nodes if n.get('package')=='com.android.settings' and n.get('resource-id','').endswith('/settings_button')]
    owner_evidence={}
    _owner_evidence(owner_evidence,'input','not_observed')
    owner=anr_owner_diagnostic(evidence=owner_evidence) if any(n.get('package')=='android' and n.get('resource-id')=='android:id/aerr_close' for n in nodes) else {'category':'unknown','correlated':False}
    print('Owned VPN Settings navigation unavailable: '+repr({'packages':packages,'resources':resources,'owned':owned,'gears':gears,'focusedSettingsANR':last_settings_anr,'focusSnapshot':last_focus_snapshot,'anrOwner':owner,'launchStatus':launch_observations,'anrEvidence':owner_evidence}),flush=True)
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
