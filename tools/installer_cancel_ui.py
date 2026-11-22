"""Exercise ordinary app controls, Android's file picker and the system Cancel button on CI."""
import json
import re
import time

from emulator_policy_ui import tree, tap
from enrollment_fixture import decode
from run_vpn_process_faults import PACKAGE, adb, await_condition


def node(predicate, timeout=35, scroll=False):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        root=tree()
        target=next((item for item in root.iter("node") if item.get("enabled")=="true" and predicate(item)),None)
        if target is not None:
            return target
        if scroll:
            size=adb("shell","wm","size").decode()
            w,h=map(int,re.findall(r"(\d+)x(\d+)",size)[-1])
            adb("shell","input","swipe",str(w//2),str(h*4//5),str(w//2),str(h//3),"320")
        time.sleep(.2)
    raise AssertionError("Expected control did not appear on the disposable emulator")


def app_text(label, **options):
    return node(lambda n:n.get("package")==PACKAGE and n.get("text")==label,**options)


def home_update_control():
    # MainActivity can resume below the update entry. Find the top of its
    # scrollable content first, then traverse down using overlapping viewports.
    deadline = time.monotonic() + 65
    seeking_top = True
    previous = None
    while time.monotonic() < deadline:
        app_nodes = [item for item in tree().iter("node") if item.get("package") == PACKAGE]
        target = next((item for item in app_nodes if item.get("enabled") == "true"
                       and item.get("text") == "Обновление приложения"), None)
        if target is not None:
            return target
        scroll = next((item for item in app_nodes if item.get("scrollable") == "true"), None)
        if scroll is None:
            time.sleep(.2)
            continue
        bounds = re.fullmatch(r"\[(\d+),(\d+)\]\[(\d+),(\d+)\]", scroll.get("bounds", ""))
        if bounds is None:
            raise AssertionError("Main scrolling surface has no usable bounds")
        labels = [(item.get("text"), item.get("bounds")) for item in app_nodes if item.get("text")]
        if seeking_top and (any(label == "Secure Your Network" for label, _ in labels) or
                            labels and labels == previous):
            seeking_top = False
        previous = labels
        left, top, right, bottom = map(int, bounds.groups())
        x = str((left + right) // 2)
        upper = str(top + (bottom - top) // 4)
        lower = str(top + (bottom - top) * 3 // 4)
        start, end = (upper, lower) if seeking_top else (lower, upper)
        adb("shell", "input", "swipe", x, start, x, end, "420")
        time.sleep(.2)
    raise AssertionError("Update action not found on the main scrolling surface")


def document(name):
    def picker(n):
        return n.get("package","").endswith(".documentsui")
    def entry(n):
        return picker(n) and n.get("text")==name
    node(picker)
    root=tree()
    hit=next((n for n in root.iter("node") if entry(n)),None)
    if hit is None:
        # Open the external storage provider, whose Download directory also
        # contains files pushed by ADB and not indexed by DownloadManager.
        drawer=node(lambda n:picker(n) and n.get("content-desc","").casefold() in
                    ("show roots","open navigation drawer","show navigation drawer","показать корни","открыть панель навигации"))
        tap(drawer)
        model=adb("shell","getprop","ro.product.model").decode().strip().casefold()
        storage=node(lambda n:picker(n) and n.get("text","").casefold() in (model,"internal storage","внутренняя память"))
        tap(storage)
        tap(node(lambda n:picker(n) and n.get("text")=="Download",scroll=True))
        hit=node(entry,scroll=True)
    tap(hit)


def cancel_installer(directory, enrolled_device, installed_version, expected_version):
    offer_path=directory/"syn443-update.txt"
    # Read the addressed public offer to check the fixture recipient. The app
    # performs its own signature, policy, signer, hash and compatibility checks.
    payload=json.loads(decode(offer_path.read_text(encoding="ascii").split(".")[1]))
    assert payload["scope"]["deviceId"]==enrolled_device
    assert installed_version()==expected_version
    folder="/sdcard/Download/"
    # Refuse to overwrite any pre-existing shared files, even on this known CI AVD.
    files=("syn443-update.txt","syn443-candidate.apk")
    if set(files) & set(adb("shell","ls","-1",folder).decode().splitlines()):
        raise AssertionError("Installer fixtures already exist")
    adb("push",str(offer_path),folder+files[0],timeout=30)
    try:
        adb("push",str(directory/"new-debug.apk"),folder+files[1],timeout=120)
        # This is an OS setting on the disposable emulator only. Restore the
        # original app-op mode even on failure and never select Install.
        original=adb("shell","appops","get",PACKAGE,"REQUEST_INSTALL_PACKAGES").decode()
        found=re.search(r"REQUEST_INSTALL_PACKAGES:\s*(allow|deny|ignore|default|foreground)\b",original)
        mode=found.group(1) if found else "default"
        try:
            adb("shell","appops","set",PACKAGE,"REQUEST_INSTALL_PACKAGES","allow")
            adb("shell","am","start","-W","-n",PACKAGE+"/.MainActivity")
            tap(home_update_control())
            tap(app_text("Выбрать манифест обновления"))
            document(files[0])
            tap(app_text("Выбрать APK"))
            document(files[1])
            tap(app_text("Перейти к установке",timeout=90))
            def platform(n):
                return n.get("package","") in ("com.android.packageinstaller","com.google.android.packageinstaller",
                                                "com.android.permissioncontroller","com.google.android.permissioncontroller")
            root=node(lambda n:platform(n) and n.get("text","").casefold() in ("update","install","обновить","установить"))
            system=root.get("package")
            # A source-permission or Play Protect dialog is not the update confirmation.
            negative=node(lambda n:n.get("package")==system and n.get("text","").casefold() in ("cancel","отмена","отменить"))
            def staged():
                return adb("shell","run-as",PACKAGE,"ls","cache/verified-updates").decode().split()
            assert len(staged())==1
            tap(negative)
            app_text("Окно установки закрыто.")
            await_condition(lambda:not staged(),15)
            assert installed_version()==expected_version
        finally:
            adb("shell","appops","set",PACKAGE,"REQUEST_INSTALL_PACKAGES",mode)
    finally:
        for name in files:
            adb("shell","rm","-f",folder+name)
