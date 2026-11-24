package expensetracker;

import java.util.Locale;

/** Allow-list of expense categories (V5). The same list is enforced again by a database CHECK constraint. */
public enum Category {
    FOOD, TRANSPORT, HOUSING, UTILITIES, HEALTH, ENTERTAINMENT, OTHER;

    public static Category parse(String s) {
        if (s == null) throw new Errors.ValidationException("Invalid category");
        try {
            return valueOf(s.trim().toUpperCase(Locale.ROOT));
        } catch (IllegalArgumentException e) {
            throw new Errors.ValidationException("Invalid category");
        }
    }
}
