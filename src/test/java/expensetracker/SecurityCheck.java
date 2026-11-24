package expensetracker;

import expensetracker.repo.*;
import expensetracker.security.*;
import expensetracker.security.SessionManager.Session;
import expensetracker.service.*;
import expensetracker.web.WebServer;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.Connection;
import java.sql.Statement;
import java.time.Duration;
import java.time.LocalDate;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Runs the verification plan from the security documentation (Section 8) against the real code.
 * No test framework needed:   java -cp "out:lib/*" expensetracker.SecurityCheck
 */
public final class SecurityCheck {
    static int passed, failed;
    static final String PW = "correct horse battery";
    static final String TODAY = LocalDate.now().toString();

    static void check(String name, boolean ok) {
        System.out.println((ok ? "[PASS] " : "[FAIL] ") + name);
        if (ok) passed++; else failed++;
    }

    static boolean throwsA(Class<? extends Throwable> type, Runnable r) {
        try { r.run(); return false; } catch (Throwable t) { return type.isInstance(t); }
    }

    static boolean sqlFails(Database db, String sql) {
        try (Connection c = db.open(); Statement st = c.createStatement()) { st.executeUpdate(sql); return false; }
        catch (Exception e) { return true; }
    }

    public static void main(String[] args) throws Exception {
        System.setProperty("jdk.httpclient.allowRestrictedHeaders", "host");
        Path dir = Files.createTempDirectory("expense-check");
        Database db = new Database(dir.resolve("test.db"));
        UserRepository users = new UserRepository(db);
        ExpenseRepository expenseRepo = new ExpenseRepository(db);
        AuditRepository auditRepo = new AuditRepository(db);
        AuditService audit = new AuditService(auditRepo);
        SessionManager sessions = new SessionManager(Duration.ofMinutes(15), Duration.ofHours(8));
        LoginLimiter limiter = new LoginLimiter(5, Duration.ofMinutes(15));
        AuthService auth = new AuthService(users, sessions, limiter, audit);
        ExpenseService expenses = new ExpenseService(expenseRepo, audit);

        // ---------------- V1 SQL injection
        System.out.println("\n== V1 SQL injection ==");
        auth.register("alice_test", PW, "test");
        auth.register("bob_test", PW, "test");
        check("Injected username finds no user", users.findByUsername("' OR '1'='1").isEmpty());
        check("Injected username cannot log in", throwsA(Errors.AccessDeniedException.class, () -> auth.login("' OR '1'='1' --", "x", "test")));
        check("Injected password cannot log in", throwsA(Errors.AccessDeniedException.class, () -> auth.login("alice_test", "' OR '1'='1", "test")));
        Session alice = auth.login("alice_test", PW, "test");
        Session bob = auth.login("bob_test", PW, "test");
        check("Injected category filter is rejected", throwsA(Errors.ValidationException.class, () -> expenses.list(alice, "FOOD' OR '1'='1", "0")));
        check("Injected description is rejected", throwsA(Errors.ValidationException.class,
                () -> expenses.add(alice, "5.00", "FOOD", "x'); DROP TABLE expenses;--", TODAY, "test")));

        // ---------------- V2 password storage
        System.out.println("\n== V2 Password storage ==");
        String stored = users.findByUsername("alice_test").get().pwdHash();
        String stored2 = users.findByUsername("bob_test").get().pwdHash();
        check("Stored value is a salted PBKDF2 hash", stored.startsWith("pbkdf2$600000$"));
        check("Stored value does not contain the password", !stored.contains(PW));
        check("Same password gives different hashes (unique salts)", !stored.equals(stored2));
        check("Correct password verifies", PasswordHasher.verify(PW.toCharArray(), stored));
        check("Wrong password fails", !PasswordHasher.verify("wrong password!!".toCharArray(), stored));
        check("Corrupted hash fails safely", !PasswordHasher.verify(PW.toCharArray(), "garbage"));

        // ---------------- V3 brute force
        System.out.println("\n== V3 Brute force ==");
        auth.register("carol_test", PW, "test");
        for (int i = 0; i < 5; i++) { try { auth.login("carol_test", "wrong password " + i, "test"); } catch (Errors.AccessDeniedException ignored) { } }
        check("Account locked after 5 failures (correct password now refused)", throwsA(Errors.AccessDeniedException.class, () -> auth.login("carol_test", PW, "test")));
        String m1 = msg(() -> auth.login("nobody_here", "whatever password", "test"));
        String m2 = msg(() -> auth.login("alice_test", "wrong password!!", "test"));
        check("Unknown user and wrong password give the same message", m1 != null && m1.equals(m2));
        check("Weak password rejected at registration", throwsA(Errors.ValidationException.class, () -> auth.register("dave_test", "short", "test")));

        // ---------------- V4 access control
        System.out.println("\n== V4 Access control (IDOR) ==");
        long id = expenses.add(alice, "20.00", "FOOD", "Lunch", TODAY, "test");
        check("Other user cannot delete my expense", throwsA(Errors.NotFoundException.class, () -> expenses.delete(bob, "" + id, "test")));
        check("Other user cannot update my expense", throwsA(Errors.NotFoundException.class, () -> expenses.update(bob, "" + id, "1.00", "FOOD", "hacked", TODAY, "test")));
        check("Other user does not see my expense", expenses.list(bob, null, "0").count() == 0);
        check("My expense is untouched", expenses.list(alice, null, "0").count() == 1);
        check("No session means access denied", throwsA(Errors.AccessDeniedException.class, () -> expenses.list(null, null, "0")));

        // ---------------- V5 validation
        System.out.println("\n== V5 Input validation ==");
        for (String bad : new String[]{"-5", "0", "1e308", "10.999", "1000000.01", "abc", "", "NaN", "5,00"})
            check("Amount rejected: '" + bad + "'", throwsA(Errors.ValidationException.class, () -> expenses.add(alice, bad, "FOOD", "x", TODAY, "t")));
        check("Description of 101 characters rejected", throwsA(Errors.ValidationException.class, () -> expenses.add(alice, "1", "FOOD", "a".repeat(101), TODAY, "t")));
        check("Unknown category rejected", throwsA(Errors.ValidationException.class, () -> expenses.add(alice, "1", "WEAPONS", "x", TODAY, "t")));
        check("Far-future date rejected", throwsA(Errors.ValidationException.class, () -> expenses.add(alice, "1", "FOOD", "x", "2999-01-01", "t")));
        check("Malformed date rejected", throwsA(Errors.ValidationException.class, () -> expenses.add(alice, "1", "FOOD", "x", "yesterday", "t")));
        check("Valid amount stored exactly (12.34 -> 1234 cents)", Validator.amount("12.34") == 1234);
        check("Database CHECK blocks negative amount even if code is bypassed",
                sqlFails(db, "INSERT INTO expenses(user_id, amount_cents, category, description, spent_on, created_at) VALUES (" + alice.userId + ",-5,'FOOD','x','2026-01-01','t')"));

        // ---------------- V8 audit
        System.out.println("\n== V8 Audit trail ==");
        expenses.delete(alice, "" + id, "test");
        check("Failed logins were recorded", auditRepo.count("LOGIN", "FAILED") > 0);
        check("Add and delete were recorded", auditRepo.count("ADD_EXPENSE", "OK") > 0 && auditRepo.count("DELETE_EXPENSE", "OK") > 0);
        check("Blocked cross-user attempt was recorded", auditRepo.count("DELETE_EXPENSE", "NOT_FOUND") > 0);
        check("Audit log rows cannot be deleted", sqlFails(db, "DELETE FROM audit_log"));
        check("Audit log rows cannot be altered", sqlFails(db, "UPDATE audit_log SET outcome = 'OK'"));

        // ---------------- V9 limits
        System.out.println("\n== V9 Resource limits ==");
        for (int i = 0; i < 12; i++) expenses.add(alice, "1.00", "OTHER", "item " + i, TODAY, "t");
        check("List is paged (max 10 per page)", expenses.list(alice, null, "0").items().size() == 10);
        check("Page 2 has the remainder", expenses.list(alice, null, "1").items().size() == 2);
        check("Absurd page number rejected", throwsA(Errors.ValidationException.class, () -> expenses.list(alice, null, "99999999")));
        RateLimiter rl = new RateLimiter(3, 60_000);
        check("Rate limiter blocks the 4th request in a window", rl.allow("x") && rl.allow("x") && rl.allow("x") && !rl.allow("x"));

        // ---------------- V10 sessions
        System.out.println("\n== V10 Sessions ==");
        check("Token is 256-bit (43 URL-safe chars)", alice.token.length() == 43 && alice.token.matches("[A-Za-z0-9_-]+"));
        check("Tokens are unique per login", !alice.token.equals(auth.login("alice_test", PW, "test").token));
        check("Tampered token rejected", sessions.get(alice.token.substring(0, 42) + "x").isEmpty());
        SessionManager shortLived = new SessionManager(Duration.ofMillis(200), Duration.ofHours(1));
        Session tmp = shortLived.create(1, "x");
        Thread.sleep(350);
        check("Idle session expires", shortLived.get(tmp.token).isEmpty());
        Session s3 = sessions.create(alice.userId, "alice_test");
        sessions.invalidate(s3.token);
        check("Logged-out token no longer works", sessions.get(s3.token).isEmpty());

        // ---------------- V11 CSV
        System.out.println("\n== V11 CSV injection ==");
        check("Formula is neutralised", Csv.safe("=cmd|' /C calc'!A0").startsWith("\"'="));
        check("+, -, @ are neutralised", Csv.safe("+1").startsWith("\"'+") && Csv.safe("-1").startsWith("\"'-") && Csv.safe("@x").startsWith("\"'@"));
        check("Quotes are escaped", Csv.safe("a\"b").equals("\"a\"\"b\""));

        // ---------------- HTTP layer: V6, V10, CSRF, headers
        System.out.println("\n== HTTP layer (headers, cookies, CSRF, errors) ==");
        httpChecks(auth, expenses, sessions);

        System.out.println("\nResult: " + passed + " passed, " + failed + " failed.");
        System.exit(failed == 0 ? 0 : 1);
    }

    static String msg(Runnable r) { try { r.run(); return null; } catch (RuntimeException e) { return e.getMessage(); } }

    // ------------------------------------------------------------------ HTTP checks

    static void httpChecks(AuthService auth, ExpenseService expenses, SessionManager sessions) throws Exception {
        WebServer web = new WebServer(0, auth, expenses, sessions, new RateLimiter(10_000, 60_000));
        web.start();
        String base = "http://127.0.0.1:" + web.port();
        String origin = base;
        HttpClient http = HttpClient.newHttpClient();

        HttpResponse<String> r = send(http, "GET", base + "/", null, null);
        check("Home page served", r.statusCode() == 200 && r.body().contains("Secure Daily Expense Tracker"));
        check("Content-Security-Policy header present", r.headers().firstValue("Content-Security-Policy").orElse("").contains("default-src 'none'"));
        check("X-Frame-Options DENY and nosniff present",
                "DENY".equals(r.headers().firstValue("X-Frame-Options").orElse("")) && "nosniff".equals(r.headers().firstValue("X-Content-Type-Options").orElse("")));
        check("Path traversal gets 404", send(http, "GET", base + "/..%2f..%2fetc%2fpasswd", null, null).statusCode() == 404);
        check("Unknown API path gets generic 404", send(http, "GET", base + "/api/nope", null, null).statusCode() == 404);
        check("Wrong method on static page gets 405", send(http, "POST", base + "/", "", null).statusCode() == 405);
        check("Unauthenticated expense list gets 401", send(http, "GET", base + "/api/expenses", null, null).statusCode() == 401);
        check("Unauthenticated export gets 401", send(http, "GET", base + "/api/export", null, null).statusCode() == 401);
        check("Unauthenticated add gets 401", sendForm(http, base + "/api/expenses", "amount=1&category=FOOD&description=x&date=" + TODAY, null, null, origin).statusCode() == 401);

        sendForm(http, base + "/api/register", "username=httpuser&password=" + PW.replace(" ", "+"), null, null, origin);
        HttpResponse<String> login = sendForm(http, base + "/api/login", "username=httpuser&password=" + PW.replace(" ", "+"), null, null, origin);
        check("Login succeeds over HTTP", login.statusCode() == 200);
        String setCookie = login.headers().firstValue("Set-Cookie").orElse("");
        check("Session cookie is HttpOnly and SameSite=Strict", setCookie.contains("HttpOnly") && setCookie.contains("SameSite=Strict"));
        String cookie = setCookie.split(";")[0];
        Matcher m = Pattern.compile("\"csrf\":\"([^\"]+)\"").matcher(login.body());
        check("CSRF token returned", m.find());
        String csrf = m.group(1);

        String form = "amount=9.99&category=FOOD&description=Coffee&date=" + TODAY;
        check("Add without CSRF token is refused (403)", sendForm(http, base + "/api/expenses", form, cookie, null, origin).statusCode() == 403);
        check("Add with wrong CSRF token is refused (403)", sendForm(http, base + "/api/expenses", form, cookie, "wrong", origin).statusCode() == 403);
        check("Add from foreign Origin is refused (403)", sendForm(http, base + "/api/expenses", form, cookie, csrf, "http://evil.example").statusCode() == 403);
        HttpResponse<String> add = sendForm(http, base + "/api/expenses", form, cookie, csrf, origin);
        check("Add with valid session, CSRF token and Origin works", add.statusCode() == 201);
        Matcher idm = Pattern.compile("\"id\":(\\d+)").matcher(add.body());
        idm.find();
        String expenseId = idm.group(1);

        HttpResponse<String> list = send(http, "GET", base + "/api/expenses", null, cookie);
        check("List returns the expense", list.statusCode() == 200 && list.body().contains("Coffee"));

        HttpResponse<String> xss = sendForm(http, base + "/api/expenses", "amount=1&category=FOOD&description=%3Cscript%3Ealert(1)%3C%2Fscript%3E&date=" + TODAY, cookie, csrf, origin);
        check("Script tag in description is rejected (400)", xss.statusCode() == 400);
        check("Oversized request body rejected (413)", sendForm(http, base + "/api/expenses", "description=" + "x".repeat(10_000), cookie, csrf, origin).statusCode() == 413);
        check("Wrong content type rejected (400)", send(http, "POST", base + "/api/expenses", "{}", cookie, "application/json", csrf, origin).statusCode() == 400);

        HttpResponse<String> host = sendWithHost(http, base + "/", "evil.example");
        check("Foreign Host header refused (403)", host.statusCode() == 403);

        HttpResponse<String> csv = send(http, "GET", base + "/api/export", null, cookie);
        check("CSV export works for the owner", csv.statusCode() == 200 && csv.body().contains("Coffee") && csv.headers().firstValue("Content-Disposition").orElse("").contains("attachment"));

        // Another user cannot touch this expense through the API
        sendForm(http, base + "/api/register", "username=otheruser&password=" + PW.replace(" ", "+"), null, null, origin);
        HttpResponse<String> l2 = sendForm(http, base + "/api/login", "username=otheruser&password=" + PW.replace(" ", "+"), null, null, origin);
        String cookie2 = l2.headers().firstValue("Set-Cookie").orElse("").split(";")[0];
        Matcher m2 = Pattern.compile("\"csrf\":\"([^\"]+)\"").matcher(l2.body());
        m2.find();
        check("Other user cannot delete my expense via API (404)", sendForm(http, base + "/api/expenses/delete", "id=" + expenseId, cookie2, m2.group(1), origin).statusCode() == 404);

        HttpResponse<String> lo = sendForm(http, base + "/api/logout", "", cookie, csrf, origin);
        check("Logout works", lo.statusCode() == 200);
        check("Old cookie is rejected after logout (401)", send(http, "GET", base + "/api/expenses", null, cookie).statusCode() == 401);
        check("Error bodies contain no stack traces or SQL", !list.body().contains("Exception") && !xss.body().contains("at expensetracker"));

        web.stop();
    }

    static HttpResponse<String> send(HttpClient http, String method, String url, String body, String cookie) throws Exception {
        return send(http, method, url, body, cookie, "application/x-www-form-urlencoded", null, null);
    }

    static HttpResponse<String> send(HttpClient http, String method, String url, String body, String cookie,
                                     String contentType, String csrf, String origin) throws Exception {
        HttpRequest.Builder b = HttpRequest.newBuilder(URI.create(url));
        if (cookie != null) b.header("Cookie", cookie);
        if (csrf != null) b.header("X-CSRF-Token", csrf);
        if (origin != null) b.header("Origin", origin);
        if (body != null) b.header("Content-Type", contentType);
        b.method(method, body == null ? HttpRequest.BodyPublishers.noBody() : HttpRequest.BodyPublishers.ofString(body));
        return http.send(b.build(), HttpResponse.BodyHandlers.ofString());
    }

    static HttpResponse<String> sendForm(HttpClient http, String url, String body, String cookie, String csrf, String origin) throws Exception {
        return send(http, "POST", url, body, cookie, "application/x-www-form-urlencoded", csrf, origin);
    }

    static HttpResponse<String> sendWithHost(HttpClient http, String url, String host) throws Exception {
        HttpRequest req = HttpRequest.newBuilder(URI.create(url)).header("Host", host).GET().build();
        return http.send(req, HttpResponse.BodyHandlers.ofString());
    }
}
