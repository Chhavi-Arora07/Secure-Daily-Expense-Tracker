package expensetracker.security;

import expensetracker.Errors.ValidationException;

import java.math.BigDecimal;
import java.time.LocalDate;
import java.time.format.DateTimeParseException;
import java.util.Locale;
import java.util.regex.Pattern;

/** Allow-list validation. Anything that does not match is rejected, never "fixed" (V5, Fail Securely). */
public final class Validator {
    private static final Pattern USERNAME = Pattern.compile("[A-Za-z0-9_]{3,30}");
    private static final Pattern AMOUNT = Pattern.compile("\\d{1,7}(\\.\\d{1,2})?");
    private static final Pattern DESCRIPTION = Pattern.compile("[\\p{L}\\p{N} .,'\\-]{0,100}");
    private static final Pattern DIGITS = Pattern.compile("\\d{1,18}");
    private static final BigDecimal MAX_AMOUNT = new BigDecimal("1000000");
    public static final LocalDate MIN_DATE = LocalDate.of(2000, 1, 1);
    public static final int MAX_PAGE = 10_000;

    private Validator() {}

    public static boolean isValidUsername(String s) { return s != null && USERNAME.matcher(s).matches(); }

    public static String username(String s) {
        String t = s == null ? "" : s.trim();
        if (!USERNAME.matcher(t).matches()) throw new ValidationException("Username must be 3 to 30 letters, digits or underscores");
        return t;
    }

    public static void password(String pw, String username) {
        if (pw == null || pw.length() < 12 || pw.length() > 128) throw new ValidationException("Password must be 12 to 128 characters");
        if (pw.toLowerCase(Locale.ROOT).contains(username.toLowerCase(Locale.ROOT))) throw new ValidationException("Password must not contain the username");
    }

    /** @return the amount in cents. Money is never handled as double (integrity). */
    public static long amount(String s) {
        String t = s == null ? "" : s.trim();
        if (!AMOUNT.matcher(t).matches()) throw new ValidationException("Amount must be a positive number with at most 2 decimals");
        BigDecimal b = new BigDecimal(t);
        if (b.signum() <= 0 || b.compareTo(MAX_AMOUNT) > 0) throw new ValidationException("Amount must be between 0.01 and 1,000,000");
        return b.movePointRight(2).longValueExact();
    }

    public static String description(String s) {
        String t = s == null ? "" : s.trim();
        if (!DESCRIPTION.matcher(t).matches()) throw new ValidationException("Description: up to 100 letters, digits, spaces and . , ' -");
        return t;
    }

    public static LocalDate date(String s) {
        try {
            LocalDate d = LocalDate.parse(s == null ? "" : s.trim());
            if (d.isBefore(MIN_DATE) || d.isAfter(LocalDate.now().plusDays(1))) throw new ValidationException("Date is out of range");
            return d;
        } catch (DateTimeParseException e) {
            throw new ValidationException("Date must look like 2026-11-23");
        }
    }

    public static long id(String s) {
        String t = s == null ? "" : s.trim();
        if (!DIGITS.matcher(t).matches()) throw new ValidationException("Invalid id");
        return Long.parseLong(t);
    }

    public static int page(String s) {
        if (s == null || s.isBlank()) return 0;
        String t = s.trim();
        if (!t.matches("\\d{1,5}")) throw new ValidationException("Invalid page");
        int p = Integer.parseInt(t);
        if (p > MAX_PAGE) throw new ValidationException("Invalid page");
        return p;
    }
}
