package expensetracker.service;

import expensetracker.Errors;
import expensetracker.repo.UserRepository;
import expensetracker.repo.UserRepository.UserRecord;
import expensetracker.security.*;
import expensetracker.security.SessionManager.Session;

import java.util.Arrays;
import java.util.Locale;
import java.util.Optional;

/** Registration and login. Every login failure produces the same message (V3). */
public final class AuthService {
    static final String GENERIC_FAILURE = "Invalid credentials or account temporarily locked";

    private final UserRepository users;
    private final SessionManager sessions;
    private final LoginLimiter limiter;
    private final AuditService audit;

    public AuthService(UserRepository users, SessionManager sessions, LoginLimiter limiter, AuditService audit) {
        this.users = users; this.sessions = sessions; this.limiter = limiter; this.audit = audit;
    }

    public long register(String username, String password, String ip) {
        String name = Validator.username(username);
        Validator.password(password, name);
        char[] pw = password.toCharArray();
        String hash;
        try { hash = PasswordHasher.hash(pw); } finally { Arrays.fill(pw, '\0'); }
        long id = users.create(name, hash);
        audit.log(id, "REGISTER", id, "OK", ip);
        return id;
    }

    public Session login(String username, String password, String ip) {
        String key = username == null ? "" : username.trim().toLowerCase(Locale.ROOT);
        if (key.length() > 64) key = key.substring(0, 64);

        if (limiter.isLocked(key)) {
            audit.log(null, "LOGIN", null, "LOCKED", ip);
            throw new Errors.AccessDeniedException(GENERIC_FAILURE);
        }

        char[] pw = (password == null || password.length() > 128 ? "" : password).toCharArray();
        Optional<UserRecord> user = Validator.isValidUsername(key) ? users.findByUsername(key) : Optional.empty();
        boolean ok;
        try {
            // A hash is always computed, so a missing user takes as long as a wrong password.
            ok = user.isPresent() ? PasswordHasher.verify(pw, user.get().pwdHash()) : PasswordHasher.verifyDummy(pw);
        } finally {
            Arrays.fill(pw, '\0');
        }

        if (!ok) {
            limiter.recordFailure(key);
            audit.log(user.map(UserRecord::id).orElse(null), "LOGIN", null, "FAILED", ip);
            throw new Errors.AccessDeniedException(GENERIC_FAILURE);
        }
        limiter.reset(key);
        Session s = sessions.create(user.get().id(), user.get().username());
        audit.log(s.userId, "LOGIN", null, "OK", ip);
        return s;
    }

    public void logout(Session s, String ip) {
        sessions.invalidate(s.token);
        audit.log(s.userId, "LOGOUT", null, "OK", ip);
    }
}
