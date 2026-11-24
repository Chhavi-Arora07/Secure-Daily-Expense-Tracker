package expensetracker.security;

import java.util.HashMap;
import java.util.Map;

/** Simple fixed-window request limiter per client (V9). */
public final class RateLimiter {
    private final int max;
    private final long windowMs;
    private final Map<String, long[]> map = new HashMap<>();

    public RateLimiter(int maxRequests, long windowMs) { this.max = maxRequests; this.windowMs = windowMs; }

    public synchronized boolean allow(String key) {
        long now = System.currentTimeMillis();
        if (map.size() > 10_000) map.values().removeIf(v -> now - v[0] > windowMs);
        long[] v = map.computeIfAbsent(key, k -> new long[]{now, 0});
        if (now - v[0] > windowMs) { v[0] = now; v[1] = 0; }
        return ++v[1] <= max;
    }
}
