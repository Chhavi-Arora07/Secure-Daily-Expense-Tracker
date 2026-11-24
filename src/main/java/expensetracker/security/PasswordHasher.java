package expensetracker.security;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Base64;

/** Salted PBKDF2-HMAC-SHA256 with the OWASP-recommended iteration count (V2). Built into the JDK, no library needed. */
public final class PasswordHasher {
    private static final int ITERATIONS = 600_000;
    private static final int SALT_BYTES = 16;
    private static final int KEY_BITS = 256;
    private static final SecureRandom RNG = new SecureRandom();
    private static final String DUMMY = hash("not-a-real-password".toCharArray());

    private PasswordHasher() {}

    public static String hash(char[] password) {
        byte[] salt = new byte[SALT_BYTES];
        RNG.nextBytes(salt);
        byte[] h = derive(password, salt, ITERATIONS);
        Base64.Encoder e = Base64.getEncoder();
        return "pbkdf2$" + ITERATIONS + "$" + e.encodeToString(salt) + "$" + e.encodeToString(h);
    }

    /** Constant-time comparison. Any malformed stored value simply fails (fail securely). */
    public static boolean verify(char[] password, String stored) {
        try {
            String[] p = stored.split("\\$");
            if (p.length != 4 || !p[0].equals("pbkdf2")) return false;
            int iterations = Integer.parseInt(p[1]);
            if (iterations < 1000 || iterations > 5_000_000) return false;
            byte[] salt = Base64.getDecoder().decode(p[2]);
            byte[] expected = Base64.getDecoder().decode(p[3]);
            return MessageDigest.isEqual(expected, derive(password, salt, iterations));
        } catch (RuntimeException ex) {
            return false;
        }
    }

    /** Burns the same time as a real check so that unknown usernames cannot be detected by timing (V3). */
    public static boolean verifyDummy(char[] password) {
        verify(password, DUMMY);
        return false;
    }

    private static byte[] derive(char[] password, byte[] salt, int iterations) {
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_BITS);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("Password hashing unavailable", e);
        } finally {
            spec.clearPassword();
        }
    }
}
