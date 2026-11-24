package expensetracker.service;

/** CSV output encoding that neutralises spreadsheet formulas (V11). */
public final class Csv {
    private Csv() {}

    public static String safe(String v) {
        String s = v == null ? "" : v;
        if (!s.isEmpty() && "=+-@\t\r".indexOf(s.charAt(0)) >= 0) s = "'" + s;   // stop =, +, -, @ from running as a formula
        return "\"" + s.replace("\"", "\"\"") + "\"";                          // always quote and escape
    }
}
