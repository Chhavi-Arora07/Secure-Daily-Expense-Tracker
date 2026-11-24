package expensetracker.repo;

import java.sql.*;
import java.time.Instant;

/** Insert-only access to the audit log (V8). The database also blocks UPDATE and DELETE with triggers. */
public final class AuditRepository {
    private final Database db;
    public AuditRepository(Database db) { this.db = db; }

    public void insert(Long userId, String action, Long targetId, String outcome, String source) throws SQLException {
        String sql = "INSERT INTO audit_log (ts_utc, user_id, action, target_id, outcome, source) VALUES (?,?,?,?,?,?)";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setString(1, Instant.now().toString());
            if (userId == null) ps.setNull(2, Types.INTEGER); else ps.setLong(2, userId);
            ps.setString(3, action);
            if (targetId == null) ps.setNull(4, Types.INTEGER); else ps.setLong(4, targetId);
            ps.setString(5, outcome);
            ps.setString(6, source);
            ps.executeUpdate();
        }
    }

    /** Used by the verification checks. */
    public int count(String action, String outcome) throws SQLException {
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement("SELECT COUNT(*) FROM audit_log WHERE action = ? AND outcome = ?")) {
            ps.setString(1, action);
            ps.setString(2, outcome);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); return rs.getInt(1); }
        }
    }
}
