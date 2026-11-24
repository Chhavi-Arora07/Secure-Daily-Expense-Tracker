package expensetracker;

import expensetracker.repo.*;
import expensetracker.security.*;
import expensetracker.service.*;
import expensetracker.web.WebServer;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Duration;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

public final class Main {
    public static void main(String[] args) {
        // Connection time limits for the built-in HTTP server (V9). Must be set before the server class loads.
        System.setProperty("sun.net.httpserver.maxReqTime", "30");
        System.setProperty("sun.net.httpserver.maxRspTime", "30");
        try {
            Config cfg = Config.fromEnv();
            setupLogging();

            Database db = new Database(cfg.dbPath);
            UserRepository users = new UserRepository(db);
            ExpenseRepository expenseRepo = new ExpenseRepository(db);
            AuditService audit = new AuditService(new AuditRepository(db));

            SessionManager sessions = new SessionManager(Duration.ofMinutes(15), Duration.ofHours(8));
            LoginLimiter limiter = new LoginLimiter(5, Duration.ofMinutes(15));
            AuthService auth = new AuthService(users, sessions, limiter, audit);
            ExpenseService expenses = new ExpenseService(expenseRepo, audit);

            WebServer web = new WebServer(cfg.port, auth, expenses, sessions, new RateLimiter(120, 60_000));
            web.start();
            Runtime.getRuntime().addShutdownHook(new Thread(web::stop));
            System.out.println("Secure Daily Expense Tracker is running.");
            System.out.println("Open http://localhost:" + web.port() + " in your browser. Press Ctrl+C to stop.");
        } catch (Exception e) {
            // Fail closed with a short message; details go to the log, not the screen.
            System.err.println("Could not start: " + e.getMessage());
            Logger.getLogger(Main.class.getName()).log(java.util.logging.Level.SEVERE, "Startup failure", e);
            System.exit(1);
        }
    }

    private static void setupLogging() {
        try {
            Path dir = Paths.get("logs");
            Files.createDirectories(dir);
            try { Files.setPosixFilePermissions(dir, PosixFilePermissions.fromString("rwx------")); }
            catch (UnsupportedOperationException ignored) { /* e.g. Windows */ }
            FileHandler fh = new FileHandler("logs/app-%g.log", 1_000_000, 3, true);
            fh.setFormatter(new SimpleFormatter());
            Logger.getLogger("").addHandler(fh);
        } catch (IOException e) {
            System.err.println("File logging unavailable; using console only.");
        }
    }
}
