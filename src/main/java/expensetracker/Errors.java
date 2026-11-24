package expensetracker;

/** Application errors with a fixed HTTP status and a message that is always safe to show to a user. */
public final class Errors {
    private Errors() {}

    public static class AppError extends RuntimeException {
        public final int status;
        AppError(int status, String message) { super(message); this.status = status; }
    }
    public static final class ValidationException extends AppError { public ValidationException(String m) { super(400, m); } }
    public static final class AccessDeniedException extends AppError { public AccessDeniedException(String m) { super(401, m); } }
    public static final class ForbiddenException extends AppError { public ForbiddenException(String m) { super(403, m); } }
    public static final class NotFoundException extends AppError { public NotFoundException() { super(404, "Not found"); } }
    public static final class MethodNotAllowedException extends AppError { public MethodNotAllowedException() { super(405, "Method not allowed"); } }
    public static final class TooLargeException extends AppError { public TooLargeException() { super(413, "Request too large"); } }
    public static final class RateLimitedException extends AppError { public RateLimitedException(String m) { super(429, m); } }
}
