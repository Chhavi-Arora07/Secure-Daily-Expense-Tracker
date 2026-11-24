package expensetracker;

import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Configuration comes from environment variables, never from source code (V7).
 * Invalid configuration stops the program (fail securely).
 * The server always binds to the loopback address; there is deliberately no setting to expose it.
 */
public final class Config {
    public final int port;
    public final Path dbPath;

    private Config(int port, Path dbPath) { this.port = port; this.dbPath = dbPath; }

    public static Config fromEnv() {
        int port = 8080;
        String ps = System.getenv("EXPENSE_PORT");
        if (ps != null && !ps.isBlank()) {
            try { port = Integer.parseInt(ps.trim()); }
            catch (NumberFormatException e) { throw new IllegalStateException("EXPENSE_PORT must be a number"); }
        }
        if (port < 1024 || port > 65535) throw new IllegalStateException("EXPENSE_PORT must be between 1024 and 65535");
        String db = System.getenv("EXPENSE_DB");
        Path dbPath = Paths.get(db == null || db.isBlank() ? "data/expenses.db" : db);
        return new Config(port, dbPath);
    }
}
