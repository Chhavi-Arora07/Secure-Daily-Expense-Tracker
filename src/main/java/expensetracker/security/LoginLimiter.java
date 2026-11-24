package expensetracker.security;

import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

/** Temporary lockout after repeated failures (V3). Tracks unknown usernames too, so lockout reveals nothing. */
public final class LoginLimiter {
    private static final class State { int failures; Instant lastFailure; Instant lockedUntil; }

    private final int maxFailures;
    private final Duration lockFor;
    private final Map<String, State> map = new HashMap<>();

    public LoginLimiter(int maxFailures, Duration lockFor) { this.maxFailures = maxFailures; this.lockFor = lockFor; }

    public synchronized boolean isLocked(String key) {
        State s = map.get(key);
        if (s == null || s.lockedUntil == null) return false;
        if (Instant.now().isBefore(s.lockedUntil)) return true;
        map.remove(key);
        return false;
    }

    public synchronized void recordFailure(String key) {
        Instant now = Instant.now();
        if (map.size() > 10_000) purge(now);
        State s = map.computeIfAbsent(key, k -> new State());
        if (s.lastFailure != null && now.isAfter(s.lastFailure.plus(lockFor))) s.failures = 0;
        s.failures++;
        s.lastFailure = now;
        if (s.failures >= maxFailures) { s.lockedUntil = now.plus(lockFor); s.failures = 0; }
    }

    public synchronized void reset(String key) { map.remove(key); }

    private void purge(Instant now) {
        map.values().removeIf(s -> s.lockedUntil != null ? now.isAfter(s.lockedUntil) : now.isAfter(s.lastFailure.plus(lockFor)));
    }
}
