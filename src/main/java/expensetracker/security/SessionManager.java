package expensetracker.security;

import expensetracker.Errors;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** Random 256-bit tokens, idle and absolute timeouts, stored only as hashes (V10). */
public final class SessionManager {
    public static final class Session {
        public final String token;
        public final long userId;
        public final String username;
        public final String csrfToken;
        final Instant created;
        volatile Instant lastSeen;

        Session(String token, long userId, String username, String csrfToken, Instant now) {
            this.token = token; this.userId = userId; this.username = username; this.csrfToken = csrfToken;
            this.created = now; this.lastSeen = now;
        }
    }

    private static final int MAX_SESSIONS = 10_000;
    private static final SecureRandom RNG = new SecureRandom();
    private final Map<String, Session> sessions = new ConcurrentHashMap<>();
    private final Duration idle;
    private final Duration absolute;

    public SessionManager(Duration idle, Duration absolute) { this.idle = idle; this.absolute = absolute; }

    /** A new token is issued on every login, which also prevents session fixation. */
    public Session create(long userId, String username) {
        if (sessions.size() >= MAX_SESSIONS) {
            purgeExpired();
            if (sessions.size() >= MAX_SESSIONS) throw new Errors.RateLimitedException("Server busy, try again later");
        }
        Session s = new Session(randomToken(), userId, username, randomToken(), Instant.now());
        sessions.put(key(s.token), s);
        return s;
    }

    public Optional<Session> get(String token) {
        if (token == null || token.length() != 43) return Optional.empty();   // reject malformed values early
        String k = key(token);
        Session s = sessions.get(k);
        if (s == null) return Optional.empty();
        Instant now = Instant.now();
        if (now.isAfter(s.lastSeen.plus(idle)) || now.isAfter(s.created.plus(absolute))) {
            sessions.remove(k);
            return Optional.empty();
        }
        s.lastSeen = now;
        return Optional.of(s);
    }

    public void invalidate(String token) {
        if (token != null) sessions.remove(key(token));
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        sessions.values().removeIf(s -> now.isAfter(s.lastSeen.plus(idle)) || now.isAfter(s.created.plus(absolute)));
    }

    private static String randomToken() {
        byte[] raw = new byte[32];
        RNG.nextBytes(raw);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(raw);   // 43 characters
    }

    private static String key(String token) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}
