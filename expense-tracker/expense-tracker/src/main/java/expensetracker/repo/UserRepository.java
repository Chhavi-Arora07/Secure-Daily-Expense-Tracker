package expensetracker.repo;

import expensetracker.Errors;

import java.sql.*;
import java.time.Instant;
import java.util.Optional;

/** All user SQL lives here and uses PreparedStatement only (V1). */
public final class UserRepository {
    public record UserRecord(long id, String username, String pwdHash) {}

    private final Database db;
    public UserRepository(Database db) { this.db = db; }

    public Optional<UserRecord> findByUsername(String username) {
        String sql = "SELECT id, username, pwd_hash FROM users WHERE username = ?";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(5);
            ps.setString(1, username);
            try (ResultSet rs = ps.executeQuery()) {
                return rs.next() ? Optional.of(new UserRecord(rs.getLong(1), rs.getString(2), rs.getString(3))) : Optional.empty();
            }
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    public long create(String username, String pwdHash) {
        String sql = "INSERT INTO users (username, pwd_hash, created_at) VALUES (?, ?, ?)";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, username);
            ps.setString(2, pwdHash);
            ps.setString(3, Instant.now().toString());
            ps.executeUpdate();
            return lastId(c);
        } catch (SQLException e) {
            if (e.getMessage() != null && e.getMessage().contains("UNIQUE")) throw new Errors.ValidationException("Username unavailable");
            throw new IllegalStateException("Database error", e);
        }
    }

    /** Same connection, so this is the row we just inserted (works in every SQLite driver version). */
    static long lastId(Connection c) throws SQLException {
        try (Statement st = c.createStatement(); ResultSet rs = st.executeQuery("SELECT last_insert_rowid()")) {
            rs.next();
            return rs.getLong(1);
        }
    }
}
