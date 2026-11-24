package expensetracker.service;

import expensetracker.Category;
import expensetracker.Errors;
import expensetracker.repo.ExpenseRepository;
import expensetracker.repo.ExpenseRepository.Expense;
import expensetracker.repo.ExpenseRepository.Summary;
import expensetracker.security.SessionManager.Session;
import expensetracker.security.Validator;

import java.time.LocalDate;
import java.util.List;
import java.util.Locale;

/**
 * The single enforcement point for authorisation and validation (complete mediation, V4, V5).
 * Every method requires a valid session and uses only the user id stored in that session.
 */
public final class ExpenseService {
    public static final int PAGE_SIZE = 10;
    public record Page(List<Expense> items, int page, int pageSize, long count, long totalCents) {}

    private final ExpenseRepository repo;
    private final AuditService audit;

    public ExpenseService(ExpenseRepository repo, AuditService audit) { this.repo = repo; this.audit = audit; }

    public long add(Session s, String amount, String category, String description, String date, String ip) {
        require(s);
        long cents = Validator.amount(amount);
        Category cat = Category.parse(category);
        String desc = Validator.description(description);
        LocalDate d = Validator.date(date);
        long id = repo.insert(s.userId, cents, cat, desc, d);
        audit.log(s.userId, "ADD_EXPENSE", id, "OK", ip);
        return id;
    }

    public void update(Session s, String idText, String amount, String category, String description, String date, String ip) {
        require(s);
        long id = Validator.id(idText);
        long cents = Validator.amount(amount);
        Category cat = Category.parse(category);
        String desc = Validator.description(description);
        LocalDate d = Validator.date(date);
        if (!repo.update(s.userId, id, cents, cat, desc, d)) {
            audit.log(s.userId, "UPDATE_EXPENSE", id, "NOT_FOUND", ip);
            throw new Errors.NotFoundException();      // same answer for "missing" and "someone else's"
        }
        audit.log(s.userId, "UPDATE_EXPENSE", id, "OK", ip);
    }

    public void delete(Session s, String idText, String ip) {
        require(s);
        long id = Validator.id(idText);
        if (!repo.delete(s.userId, id)) {
            audit.log(s.userId, "DELETE_EXPENSE", id, "NOT_FOUND", ip);
            throw new Errors.NotFoundException();
        }
        audit.log(s.userId, "DELETE_EXPENSE", id, "OK", ip);
    }

    public Page list(Session s, String category, String pageText) {
        require(s);
        Category cat = (category == null || category.isBlank()) ? null : Category.parse(category);
        int page = Validator.page(pageText);
        List<Expense> items = repo.list(s.userId, cat, PAGE_SIZE, page * PAGE_SIZE);
        Summary sum = repo.summary(s.userId, cat);
        return new Page(items, page, PAGE_SIZE, sum.count(), sum.totalCents());
    }

    public String exportCsv(Session s, String ip) {
        require(s);
        StringBuilder sb = new StringBuilder("\"Date\",\"Category\",\"Amount\",\"Description\"\r\n");
        for (Expense e : repo.all(s.userId, 10_000)) {
            sb.append(Csv.safe(e.spentOn())).append(',')
              .append(Csv.safe(e.category())).append(',')
              .append(Csv.safe(money(e.amountCents()))).append(',')
              .append(Csv.safe(e.description())).append("\r\n");
        }
        audit.log(s.userId, "EXPORT", null, "OK", ip);
        return sb.toString();
    }

    public static String money(long cents) {
        return String.format(Locale.ROOT, "%d.%02d", cents / 100, cents % 100);
    }

    private static void require(Session s) {
        if (s == null) throw new Errors.AccessDeniedException("Not signed in");   // deny by default
    }
}
