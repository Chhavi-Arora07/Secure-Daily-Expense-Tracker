package expensetracker.repo;

import expensetracker.Category;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.stream.Collectors;

/** Opens connections and creates the schema. Constraints here are the last layer of defence (V5, V8). */
public final class Database {
    private final String url;

    public Database(Path file) throws SQLException, IOException {
        try {
            Class.forName("org.sqlite.JDBC");
        } catch (ClassNotFoundException e) {
            throw new IllegalStateException("SQLite driver not found. Put the sqlite-jdbc and slf4j-api jars in the lib folder.");
        }
        Path abs = file.toAbsolutePath();
        Files.createDirectories(abs.getParent());
        lockDown(abs.getParent(), "rwx------");
        this.url = "jdbc:sqlite:" + abs;
        init();
        lockDown(abs, "rw-------");   // owner-only access where the OS supports POSIX permissions
    }

    public Connection open() throws SQLException {
        Connection c = DriverManager.getConnection(url);
        try (Statement s = c.createStatement()) {
            s.execute("PRAGMA foreign_keys = ON");
            s.execute("PRAGMA busy_timeout = 5000");
        }
        return c;
    }

    private void init() throws SQLException {
        String cats = Arrays.stream(Category.values()).map(c -> "'" + c.name() + "'").collect(Collectors.joining(","));
        String[] ddl = {
            "CREATE TABLE IF NOT EXISTS users (" +
            " id INTEGER PRIMARY KEY AUTOINCREMENT," +
            " username TEXT NOT NULL UNIQUE COLLATE NOCASE CHECK (length(username) BETWEEN 3 AND 30)," +
            " pwd_hash TEXT NOT NULL," +
            " created_at TEXT NOT NULL)",

            "CREATE TABLE IF NOT EXISTS expenses (" +
            " id INTEGER PRIMARY KEY AUTOINCREMENT," +
            " user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE," +
            " amount_cents INTEGER NOT NULL CHECK (amount_cents > 0 AND amount_cents <= 100000000)," +
            " category TEXT NOT NULL CHECK (category IN (" + cats + "))," +
            " description TEXT NOT NULL CHECK (length(description) <= 100)," +
            " spent_on TEXT NOT NULL," +
            " created_at TEXT NOT NULL)",

            "CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, spent_on DESC)",

            "CREATE TABLE IF NOT EXISTS audit_log (" +
            " id INTEGER PRIMARY KEY AUTOINCREMENT," +
            " ts_utc TEXT NOT NULL, user_id INTEGER, action TEXT NOT NULL," +
            " target_id INTEGER, outcome TEXT NOT NULL, source TEXT)",

            // Append-only audit log: rows can never be changed or removed (V8)
            "CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log " +
            "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END",
            "CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log " +
            "BEGIN SELECT RAISE(ABORT, 'audit log is append-only'); END"
        };
        try (Connection c = open(); Statement st = c.createStatement()) {
            for (String sql : ddl) st.execute(sql);
        }
    }

    private static void lockDown(Path p, String perms) {
        try { Files.setPosixFilePermissions(p, PosixFilePermissions.fromString(perms)); }
        catch (UnsupportedOperationException | IOException ignored) { /* not supported on this OS */ }
    }
}
