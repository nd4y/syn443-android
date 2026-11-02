package io.syn443.android.vpn;
import android.os.ParcelFileDescriptor;
interface IPlatform {
    boolean protect(in ParcelFileDescriptor fd, String token);
    byte[] exchangeDNS(in byte[] query, String token);
    String physicalInterfaces(String token);
    oneway void overlayState(String token, String state);
    oneway void overlayIdentity(String token, String proof);
    oneway void routeState(String token, String state);
    oneway void event(String token, int kind);
}
