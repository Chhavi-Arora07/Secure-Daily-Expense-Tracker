# Secure Daily Expense Tracker

A small Java web application (back end and front end) for recording daily expenses, built to demonstrate
secure coding. It implements the controls described in *Secure_Expense_Tracker_Security_Documentation.pdf*
(secure architecture principles, SSDLC, STRIDE, DREAD).

* **Back end:** Java 17+, the JDK's built-in HTTP server, JDBC, SQLite
* **Front end:** plain HTML, CSS and JavaScript served by the same program
* **Only dependency:** the SQLite driver (plus the small `slf4j-api` library it needs)

## What you need

1. **JDK 17 or newer** (check with `java -version` and `javac -version`)
2. Two jar files in the `lib` folder. Links are in `lib/README.txt`.
   Copy `sqlite-jdbc-3.46.1.3.jar` and `slf4j-api-1.7.36.jar` into `lib`.

## Build and run

| Step | Windows | Linux / macOS |
|---|---|---|
| Build | `build.bat` | `./build.sh` |
| Run the app | `run.bat` | `./run.sh` |
| Run the security checks | `run.bat check` | `./run.sh check` |

Then open **http://localhost:8080** in a browser, create an account (password of at least 12 characters)
and sign in.

Alternative with Maven: `mvn clean package`, then `java -jar target/expense-tracker.jar`.

### Optional settings (environment variables)

| Variable | Default | Meaning |
|---|---|---|
| `EXPENSE_PORT` | `8080` | Port, 1024 to 65535 |
| `EXPENSE_DB` | `data/expenses.db` | Database file location |

The server always listens on `127.0.0.1` only, so other computers on the network cannot reach it.

## Project layout

```
src/main/java/expensetracker/
  Main, Config, Errors, Category      start-up, configuration, safe error types, category allow-list
  web/       WebServer, Json          controller layer: HTTP, cookies, CSRF, headers
  service/   AuthService, ExpenseService, AuditService, Csv     business rules and authorisation
  repo/      Database, UserRepository, ExpenseRepository, AuditRepository    the only place with SQL
  security/  PasswordHasher, SessionManager, LoginLimiter, RateLimiter, Validator
src/main/resources/web/               index.html, app.js, style.css
src/test/java/expensetracker/         SecurityCheck (77 automated checks, no test framework needed)
```

## Where each vulnerability from the document is handled

| ID | Vulnerability | Control | Code |
|---|---|---|---|
| V1 | SQL injection | `PreparedStatement` everywhere, SQL only in the repository layer | `repo/*Repository` |
| V2 | Weak password storage | Salted PBKDF2-HMAC-SHA256, 600,000 iterations, constant-time compare | `PasswordHasher` |
| V3 | Brute force | 5 failures lock the name for 15 minutes, identical error message, timing equalised for unknown users | `AuthService`, `LoginLimiter` |
| V4 | Broken access control / IDOR | Every query has `AND user_id = ?`, service layer requires a session, same 404 for missing and foreign ids | `ExpenseService`, `ExpenseRepository` |
| V5 | Input validation | Allow-list validation, money as `BigDecimal` and cents, database `CHECK` constraints | `Validator`, `Database` |
| V6 | Error and log leaks | Generic message plus reference id for the user, details only in `logs/`, no secrets logged | `WebServer.handle` |
| V7 | Hard-coded secrets | No secrets in the code, configuration from environment, owner-only file permissions | `Config`, `Database` |
| V8 | No audit trail | Audit table, database triggers block UPDATE and DELETE | `AuditService`, `Database` |
| V9 | Resource exhaustion | Paging, body size limit, request rate limit, bounded thread pool, query timeouts, time limits | `WebServer`, `ExpenseService` |
| V10 | Weak sessions | 256-bit random token stored as a hash, 15 min idle and 8 h absolute timeout, new token on login | `SessionManager` |
| V11 | CSV injection | Leading `= + - @` neutralised, fields quoted | `Csv` |
| V12 | Vulnerable dependencies | One pinned runtime dependency (plus slf4j-api); scan with OWASP Dependency-Check if required | `pom.xml` |

Web-specific protections that go with these: `HttpOnly` and `SameSite=Strict` cookie, CSRF token on every
state-changing request, `Origin` and `Host` checks, Content-Security-Policy and other security headers,
and a front end that writes data with `textContent` only (never `innerHTML`).

## Known limitations (worth stating in your report)

* **No HTTPS.** The app is meant for `localhost` use. If it were ever exposed to a network it must sit behind
  an HTTPS reverse proxy and the cookie should also get the `Secure` flag.
* **Database file is not encrypted.** It is protected by file permissions only (owner-only on Linux/macOS;
  on Windows it relies on the user's profile permissions).
* **Lockout is per username**, so someone could deliberately lock another person's account for 15 minutes.
  This is a conscious trade-off in favour of blocking guessing.
* **Sessions live in memory**, so everyone is signed out when the app restarts.
* **Password memory.** The password arrives as a `String` from the HTTP body, which Java cannot wipe.
  The `char[]` copies the app makes are wiped after hashing.
