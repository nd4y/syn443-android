package io.syn443.emulatorheap;

/** Closed numeric JSON only. This proves the probe VM's capacity, not system_server's heap. */
final class VmMemorySnapshot {
    static final long MAX_BYTES = 2L * 1024 * 1024 * 1024;
    static final long MAX_TIME = 9_007_199_254_740_991L;
    static final int MAX_JSON = 512;

    private VmMemorySnapshot() {}

    static String encode(long maximum, long total, long free, int pid, long uptime) {
        if (maximum < 1 || maximum > MAX_BYTES || total < 0 || total > maximum
                || free < 0 || free > total || pid < 1 || uptime < 0 || uptime > MAX_TIME) {
            throw new IllegalArgumentException("invalid_snapshot");
        }
        String result = "{\"schemaVersion\":1,\"maxBytes\":" + maximum
                + ",\"totalBytes\":" + total + ",\"freeBytes\":" + free
                + ",\"pid\":" + pid + ",\"uptimeMs\":" + uptime + "}";
        if (result.length() > MAX_JSON) {
            throw new IllegalArgumentException("invalid_snapshot");
        }
        return result;
    }
}
