package no.bufferoverflow.inshare.loggers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;

/**
 * Logs actions related to notes, including creation, editing, deletion, and sharing.
 */
@Component
public class NoteActionLogger {
    /** Logger for note actions */
    private static final Logger logger = LoggerFactory.getLogger(NoteActionLogger.class);

    /**
     * Logs when a note is created.
     *
     * @param userId the ID of the user creating the note
     * @param noteId the ID of the created note
     */
    public void logCreateNote(String userId, String noteId) {
        logger.info("Action: CREATE, User ID: {}, Note ID: {}, Timestamp: {}", userId, noteId, LocalDateTime.now());
    }

    /**
     * Logs when a note is edited.
     *
     * @param userId the ID of the user editing the note
     * @param noteId the ID of the edited note
     */
    public void logEditNote(String userId, String noteId) {
        logger.info("Action: EDIT, User ID: {}, Note ID: {}, Timestamp: {}", userId, noteId, LocalDateTime.now());
    }

    /**
     * Logs when a note is deleted.
     *
     * @param userId the ID of the user deleting the note
     * @param noteId the ID of the deleted note
     */
    public void logDeleteNote(String userId, String noteId) {
        logger.warn("Action: DELETE, User ID: {}, Note ID: {}, Timestamp: {}", userId, noteId, LocalDateTime.now());
    }

    /**
     * Logs when a note is shared.
     *
     * @param userId the ID of the user sharing the note
     * @param noteId the ID of the shared note
     * @param targetUserId the ID of the user with whom the note is shared
     */
    public void logShareNote(String userId, String noteId, String targetUserId) {
        logger.info("Action: SHARE, User ID: {}, Note ID: {}, Target User ID: {}, Timestamp: {}", 
                    userId, noteId, targetUserId, LocalDateTime.now());
    }

    /**
     * Logs when note ownership is transferred.
     *
     * @param userId the ID of the current owner
     * @param noteId the ID of the note being transferred
     * @param newOwnerId the ID of the new owner
     */
    public void logTransferOwnership(String userId, String noteId, String newOwnerId) {
        logger.warn("Action: TRANSFER_OWNERSHIP, Current Owner ID: {}, Note ID: {}, New Owner ID: {}, Timestamp: {}", 
                    userId, noteId, newOwnerId, LocalDateTime.now());
    }
}
