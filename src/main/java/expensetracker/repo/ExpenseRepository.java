package expensetracker.repo;

import expensetracker.Category;

import java.sql.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.List;

/**
 * Every query is filtered by user_id, so a user can never reach another user's rows (V4),
 * and every query is parameterised (V1). Lists are always limited (V9).
 */
public final class ExpenseRepository {
    public record Expense(long id, long amountCents, String category, String description, String spentOn) {}
    public record Summary(long count, long totalCents) {}

    private final Database db;
    public ExpenseRepository(Database db) { this.db = db; }

    public long insert(long userId, long cents, Category cat, String desc, LocalDate date) {
        String sql = "INSERT INTO expenses (user_id, amount_cents, category, description, spent_on, created_at) VALUES (?,?,?,?,?,?)";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, userId);
            ps.setLong(2, cents);
            ps.setString(3, cat.name());
            ps.setString(4, desc);
            ps.setString(5, date.toString());
            ps.setString(6, Instant.now().toString());
            ps.executeUpdate();
            return UserRepository.lastId(c);
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    public List<Expense> list(long userId, Category cat, int limit, int offset) {
        String sql = "SELECT id, amount_cents, category, description, spent_on FROM expenses " +
                     "WHERE user_id = ? AND (? IS NULL OR category = ?) ORDER BY spent_on DESC, id DESC LIMIT ? OFFSET ?";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(5);
            String cn = cat == null ? null : cat.name();
            ps.setLong(1, userId);
            ps.setString(2, cn);
            ps.setString(3, cn);
            ps.setInt(4, limit);
            ps.setInt(5, offset);
            return read(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    public Summary summary(long userId, Category cat) {
        String sql = "SELECT COUNT(*), COALESCE(SUM(amount_cents),0) FROM expenses WHERE user_id = ? AND (? IS NULL OR category = ?)";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(5);
            String cn = cat == null ? null : cat.name();
            ps.setLong(1, userId);
            ps.setString(2, cn);
            ps.setString(3, cn);
            try (ResultSet rs = ps.executeQuery()) { rs.next(); return new Summary(rs.getLong(1), rs.getLong(2)); }
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    /** @return false when no row with this id belongs to this user. */
    public boolean update(long userId, long id, long cents, Category cat, String desc, LocalDate date) {
        String sql = "UPDATE expenses SET amount_cents = ?, category = ?, description = ?, spent_on = ? WHERE id = ? AND user_id = ?";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, cents);
            ps.setString(2, cat.name());
            ps.setString(3, desc);
            ps.setString(4, date.toString());
            ps.setLong(5, id);
            ps.setLong(6, userId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    /** @return false when no row with this id belongs to this user. */
    public boolean delete(long userId, long id) {
        String sql = "DELETE FROM expenses WHERE id = ? AND user_id = ?";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setLong(1, id);
            ps.setLong(2, userId);
            return ps.executeUpdate() > 0;
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    public List<Expense> all(long userId, int max) {
        String sql = "SELECT id, amount_cents, category, description, spent_on FROM expenses WHERE user_id = ? ORDER BY spent_on DESC, id DESC LIMIT ?";
        try (Connection c = db.open(); PreparedStatement ps = c.prepareStatement(sql)) {
            ps.setQueryTimeout(10);
            ps.setLong(1, userId);
            ps.setInt(2, max);
            return read(ps);
        } catch (SQLException e) {
            throw new IllegalStateException("Database error", e);
        }
    }

    private static List<Expense> read(PreparedStatement ps) throws SQLException {
        List<Expense> out = new ArrayList<>();
        try (ResultSet rs = ps.executeQuery()) {
            while (rs.next()) out.add(new Expense(rs.getLong(1), rs.getLong(2), rs.getString(3), rs.getString(4), rs.getString(5)));
        }
        return out;
    }
}
