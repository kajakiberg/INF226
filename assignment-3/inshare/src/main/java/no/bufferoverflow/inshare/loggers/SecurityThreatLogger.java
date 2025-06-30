package no.bufferoverflow.inshare.loggers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Logs security-related threats including unauthorized access.
 */
@Component
public class SecurityThreatLogger {
    /** Logger for security threat detection */
    private static final Logger logger = LoggerFactory.getLogger(SecurityThreatLogger.class);

    /**
     * Logs an unauthorized access attempt.
     *
     * @param userId the ID of the user attempting access
     * @param action the attempted action (e.g., "EDIT", "DELETE")
     * @param noteId the ID of the note the user tried to access
     */
    public void logUnauthorizedAccess(String userId, String action, String noteId) {
        logger.warn("Security Alert: Unauthorized Access Attempt - User ID: {}, Action: {}, Note ID: {}, Timestamp: {}", 
                    userId, action, noteId, LocalDateTime.now());
    }
}
