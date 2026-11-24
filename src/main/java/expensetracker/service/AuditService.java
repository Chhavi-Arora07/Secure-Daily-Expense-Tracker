package expensetracker.service;

import expensetracker.repo.AuditRepository;

import java.util.logging.Level;
import java.util.logging.Logger;

/** Records security-relevant actions (V8). Never records passwords, tokens or user-supplied text. */
public final class AuditService {
    private static final Logger LOG = Logger.getLogger(AuditService.class.getName());
    private final AuditRepository repo;

    public AuditService(AuditRepository repo) { this.repo = repo; }

    public void log(Long userId, String action, Long targetId, String outcome, String source) {
        try {
            repo.insert(userId, action, targetId, outcome, source);
        } catch (Exception e) {
            LOG.log(Level.SEVERE, "Audit write failed for action " + action, e);
        }
    }
}
