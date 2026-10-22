package io.syn443.android.vpn;
import android.os.ParcelFileDescriptor;
import io.syn443.android.vpn.IPlatform;
interface IEngineHost {
    int pid();
    oneway void start(in ParcelFileDescriptor tun, String config, String token, String interfaceName, int interfaceIndex, long leaseDeadline, IPlatform platform);
    oneway void leaseDeadline(String token, long deadline);
    oneway void stop(String token);
    oneway void pulse(String token);
    oneway void diagnoseNetBird(String token);
    oneway void networkChanged(String token, String interfaceName, int interfaceIndex);
}
