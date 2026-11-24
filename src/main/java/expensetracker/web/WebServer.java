package expensetracker.web;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import expensetracker.Errors;
import expensetracker.repo.ExpenseRepository.Expense;
import expensetracker.security.RateLimiter;
import expensetracker.security.SessionManager;
import expensetracker.security.SessionManager.Session;
import expensetracker.service.AuthService;
import expensetracker.service.ExpenseService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * Controller layer: HTTP only. Business rules live in the service layer.
 * Security controls here: loopback-only binding, Host and Origin checks, CSRF token, hardened cookie,
 * security headers, request size and rate limits, and generic error responses.
 */
public final class WebServer {
    private static final Logger LOG = Logger.getLogger(WebServer.class.getName());
    private static final int MAX_BODY = 4096;
    private static final int COOKIE_SECONDS = 8 * 3600;
    private static final String CSP = "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; " +
                                      "img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'";

    private record Asset(byte[] body, String type) {}

    private final HttpServer server;
    private final ExecutorService pool = Executors.newFixedThreadPool(8);   // bounded: cannot be flooded with threads
    private final Set<String> allowedHosts;
    private final AuthService auth;
    private final ExpenseService expenses;
    private final SessionManager sessions;
    private final RateLimiter limiter;
    private final Map<String, Asset> assets = new HashMap<>();

    public WebServer(int port, AuthService auth, ExpenseService expenses, SessionManager sessions, RateLimiter limiter) throws IOException {
        this.auth = auth; this.expenses = expenses; this.sessions = sessions; this.limiter = limiter;
        // Bound to 127.0.0.1 only: not reachable from other machines.
        server = HttpServer.create(new InetSocketAddress(InetAddress.getByAddress(new byte[]{127, 0, 0, 1}), port), 50);
        int p = server.getAddress().getPort();
        allowedHosts = Set.of("localhost:" + p, "127.0.0.1:" + p);   // blocks DNS-rebinding style requests
        assets.put("/", load("index.html", "text/html; charset=utf-8"));
        assets.put("/app.js", load("app.js", "application/javascript; charset=utf-8"));
        assets.put("/style.css", load("style.css", "text/css; charset=utf-8"));
        server.createContext("/", this::handle);
        server.setExecutor(pool);
    }

    public void start() { server.start(); }
    public void stop() { server.stop(0); pool.shutdownNow(); }
    public int port() { return server.getAddress().getPort(); }

    // ------------------------------------------------------------------ request handling

    private void handle(HttpExchange ex) throws IOException {
        try {
            securityHeaders(ex);
            String host = ex.getRequestHeaders().getFirst("Host");
            if (host == null || !allowedHosts.contains(host.toLowerCase(Locale.ROOT))) throw new Errors.ForbiddenException("Forbidden");
            String path = ex.getRequestURI().getPath();
            String method = ex.getRequestMethod();
            String ip = ex.getRemoteAddress().getAddress().getHostAddress();
            if (path.startsWith("/api/")) api(ex, method, path, ip);
            else staticFile(ex, method, path);
        } catch (Errors.AppError e) {
            sendJson(ex, e.status, Map.of("error", e.getMessage()));
        } catch (Throwable t) {
            // Fail securely: the user gets a reference id, the details stay in the protected log (V6).
            String ref = UUID.randomUUID().toString().substring(0, 8);
            LOG.log(Level.SEVERE, "Unhandled error ref=" + ref, t);
            try { sendJson(ex, 500, Map.of("error", "Something went wrong. Reference: " + ref)); } catch (Throwable ignored) { /* nothing more to do */ }
        } finally {
            ex.close();
        }
    }

    private void api(HttpExchange ex, String method, String path, String ip) throws IOException {
        if (!limiter.allow(ip)) throw new Errors.RateLimitedException("Too many requests");
        if (method.equals("POST")) checkOrigin(ex);

        switch (method + " " + path) {
            case "POST /api/register" -> {
                Map<String, String> f = readForm(ex);
                auth.register(f.get("username"), f.get("password"), ip);
                sendJson(ex, 201, Map.of("ok", true));
            }
            case "POST /api/login" -> {
                Map<String, String> f = readForm(ex);
                Session s = auth.login(f.get("username"), f.get("password"), ip);
                ex.getResponseHeaders().add("Set-Cookie", "sid=" + s.token + "; Path=/; HttpOnly; SameSite=Strict; Max-Age=" + COOKIE_SECONDS);
                sendJson(ex, 200, Map.of("username", s.username, "csrf", s.csrfToken));
            }
            case "POST /api/logout" -> {
                Session s = requireSession(ex);
                requireCsrf(ex, s);
                auth.logout(s, ip);
                ex.getResponseHeaders().add("Set-Cookie", "sid=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0");
                sendJson(ex, 200, Map.of("ok", true));
            }
            case "GET /api/me" -> {
                Session s = requireSession(ex);
                sendJson(ex, 200, Map.of("username", s.username, "csrf", s.csrfToken));
            }
            case "GET /api/expenses" -> {
                Session s = requireSession(ex);
                Map<String, String> q = readQuery(ex);
                ExpenseService.Page pg = expenses.list(s, q.get("category"), q.get("page"));
                List<Map<String, Object>> items = new ArrayList<>();
                for (Expense e : pg.items()) {
                    Map<String, Object> m = new LinkedHashMap<>();
                    m.put("id", e.id());
                    m.put("amount", ExpenseService.money(e.amountCents()));
                    m.put("category", e.category());
                    m.put("description", e.description());
                    m.put("date", e.spentOn());
                    items.add(m);
                }
                Map<String, Object> out = new LinkedHashMap<>();
                out.put("items", items);
                out.put("page", pg.page());
                out.put("pageSize", pg.pageSize());
                out.put("count", pg.count());
                out.put("total", ExpenseService.money(pg.totalCents()));
                sendJson(ex, 200, out);
            }
            case "POST /api/expenses" -> {
                Session s = requireSession(ex);
                requireCsrf(ex, s);
                Map<String, String> f = readForm(ex);
                long id = expenses.add(s, f.get("amount"), f.get("category"), f.get("description"), f.get("date"), ip);
                sendJson(ex, 201, Map.of("id", id));
            }
            case "POST /api/expenses/update" -> {
                Session s = requireSession(ex);
                requireCsrf(ex, s);
                Map<String, String> f = readForm(ex);
                expenses.update(s, f.get("id"), f.get("amount"), f.get("category"), f.get("description"), f.get("date"), ip);
                sendJson(ex, 200, Map.of("ok", true));
            }
            case "POST /api/expenses/delete" -> {
                Session s = requireSession(ex);
                requireCsrf(ex, s);
                Map<String, String> f = readForm(ex);
                expenses.delete(s, f.get("id"), ip);
                sendJson(ex, 200, Map.of("ok", true));
            }
            case "GET /api/export" -> {
                Session s = requireSession(ex);
                byte[] csv = expenses.exportCsv(s, ip).getBytes(StandardCharsets.UTF_8);
                ex.getResponseHeaders().set("Content-Type", "text/csv; charset=utf-8");
                ex.getResponseHeaders().set("Content-Disposition", "attachment; filename=\"expenses.csv\"");
                ex.getResponseHeaders().set("Cache-Control", "no-store");
                send(ex, 200, csv);
            }
            default -> throw new Errors.NotFoundException();
        }
    }

    private void staticFile(HttpExchange ex, String method, String path) throws IOException {
        if (!method.equals("GET")) {
            ex.getResponseHeaders().set("Allow", "GET");
            throw new Errors.MethodNotAllowedException();
        }
        Asset a = assets.get(path);      // exact-match allow-list: no file system access, so no path traversal
        if (a == null) throw new Errors.NotFoundException();
        ex.getResponseHeaders().set("Content-Type", a.type());
        ex.getResponseHeaders().set("Cache-Control", "no-cache");
        send(ex, 200, a.body());
    }

    // ------------------------------------------------------------------ security helpers

    private void securityHeaders(HttpExchange ex) {
        var h = ex.getResponseHeaders();
        h.set("Content-Security-Policy", CSP);
        h.set("X-Content-Type-Options", "nosniff");
        h.set("X-Frame-Options", "DENY");
        h.set("Referrer-Policy", "no-referrer");
        h.set("Cross-Origin-Resource-Policy", "same-origin");
    }

    private void checkOrigin(HttpExchange ex) {
        String origin = ex.getRequestHeaders().getFirst("Origin");
        if (origin == null) return;                 // non-browser clients send no Origin
        String host = origin.toLowerCase(Locale.ROOT);
        if (!host.startsWith("http://") || !allowedHosts.contains(host.substring(7))) throw new Errors.ForbiddenException("Forbidden");
    }

    private Session requireSession(HttpExchange ex) {
        String token = null;
        List<String> cookies = ex.getRequestHeaders().get("Cookie");
        if (cookies != null) {
            outer:
            for (String header : cookies) {
                for (String part : header.split(";")) {
                    String p = part.trim();
                    if (p.startsWith("sid=")) { token = p.substring(4); break outer; }
                }
            }
        }
        return sessions.get(token).orElseThrow(() -> new Errors.AccessDeniedException("Not signed in"));
    }

    private void requireCsrf(HttpExchange ex, Session s) {
        String sent = ex.getRequestHeaders().getFirst("X-CSRF-Token");
        if (sent == null || !MessageDigest.isEqual(sent.getBytes(StandardCharsets.UTF_8), s.csrfToken.getBytes(StandardCharsets.UTF_8)))
            throw new Errors.ForbiddenException("Forbidden");
    }

    // ------------------------------------------------------------------ input helpers

    private Map<String, String> readForm(HttpExchange ex) throws IOException {
        String ct = ex.getRequestHeaders().getFirst("Content-Type");
        if (ct == null || !ct.toLowerCase(Locale.ROOT).startsWith("application/x-www-form-urlencoded"))
            throw new Errors.ValidationException("Unsupported content type");
        try (InputStream in = ex.getRequestBody()) {
            byte[] b = in.readNBytes(MAX_BODY + 1);
            if (b.length > MAX_BODY) throw new Errors.TooLargeException();
            return parseParams(new String(b, StandardCharsets.UTF_8));
        }
    }

    private Map<String, String> readQuery(HttpExchange ex) {
        String q = ex.getRequestURI().getRawQuery();
        return parseParams(q == null ? "" : q);
    }

    private static Map<String, String> parseParams(String s) {
        Map<String, String> m = new HashMap<>();
        if (s.isEmpty()) return m;
        String[] pairs = s.split("&", 21);
        if (pairs.length > 20) throw new Errors.ValidationException("Malformed request");
        try {
            for (String pair : pairs) {
                int i = pair.indexOf('=');
                String k = URLDecoder.decode(i < 0 ? pair : pair.substring(0, i), StandardCharsets.UTF_8);
                String v = i < 0 ? "" : URLDecoder.decode(pair.substring(i + 1), StandardCharsets.UTF_8);
                m.put(k, v);
            }
        } catch (IllegalArgumentException e) {
            throw new Errors.ValidationException("Malformed request");
        }
        return m;
    }

    // ------------------------------------------------------------------ output helpers

    private void sendJson(HttpExchange ex, int status, Object body) throws IOException {
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.getResponseHeaders().set("Cache-Control", "no-store");
        send(ex, status, Json.write(body).getBytes(StandardCharsets.UTF_8));
    }

    private void send(HttpExchange ex, int status, byte[] body) throws IOException {
        ex.sendResponseHeaders(status, body.length == 0 ? -1 : body.length);
        if (body.length > 0) try (OutputStream os = ex.getResponseBody()) { os.write(body); }
    }

    private static Asset load(String name, String type) throws IOException {
        try (InputStream in = WebServer.class.getResourceAsStream("/web/" + name)) {
            if (in == null) throw new IOException("Missing resource: " + name);
            return new Asset(in.readAllBytes(), type);
        }
    }
}
