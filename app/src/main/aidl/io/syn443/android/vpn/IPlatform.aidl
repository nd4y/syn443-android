package io.syn443.android.vpn;
import android.os.ParcelFileDescriptor;
interface IPlatform {
    boolean protect(in ParcelFileDescriptor fd, String token);
    byte[] exchangeDNS(in byte[] query, String token);
    oneway void event(String token, int kind);
}
