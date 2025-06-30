package no.bufferoverflow.inshare.loggers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.security.authentication.event.AuthenticationFailureBadCredentialsEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.stereotype.Component;

import no.bufferoverflow.inshare.User;

import java.time.LocalDateTime;

/**
 * Logs authentication-related events such as logins, logouts, and failed login attempts.
 */
@Component
public class AuthenticationLogger {
    /** Logger for authentication events */
    private static final Logger logger = LoggerFactory.getLogger(AuthenticationLogger.class);

    /**
     * Logs a successful login event with user ID and timestamp.
     *
     * @param event the successful login event
     */
    @EventListener
    public void onAuthenticationSuccess(AuthenticationSuccessEvent event) {
        User user = (User) event.getAuthentication().getPrincipal();
        logger.info("Event: Login successful, User ID: {}, Timestamp: {}", user.id, LocalDateTime.now());
    }

    /**
     * Logs a successful logout event with user ID and timestamp.
     *
     * @param event the successful logout event
     */
    @EventListener
    public void onLogoutSuccess(LogoutSuccessEvent event) {
        User user = (User) event.getAuthentication().getPrincipal();
        logger.info("Event: Logout successful, User ID: {}, Timestamp: {}", user.id, LocalDateTime.now());
    }

    /**
     * Logs a failed login attempt with the attempted username and timestamp.
     *
     * @param event the failed login event
     */
    @EventListener
    public void onAuthenticationFailure(AuthenticationFailureBadCredentialsEvent event) {
        Object principal = event.getAuthentication().getPrincipal();
        String username = (principal instanceof String) ? (String) principal : "Unknown";

        logger.warn("Event: Login failed, Attempted Username: {}, Timestamp: {}", username, LocalDateTime.now());
    }
}
