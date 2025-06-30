package no.bufferoverflow.inshare.loggers;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import no.bufferoverflow.inshare.User;

import java.io.IOException;

@Component
public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private final SecurityThreatLogger securityThreatLogger;

    @Autowired
    public CustomAccessDeniedHandler(SecurityThreatLogger securityThreatLogger) {
        this.securityThreatLogger = securityThreatLogger;
    }

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response,
                       AccessDeniedException accessDeniedException) throws IOException, ServletException {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        
        // Determine the user ID or label as "Unauthenticated user" if not logged in
        String userId;
        if (authentication != null && authentication.isAuthenticated() && authentication.getPrincipal() instanceof User) {
            User currentUser = (User) authentication.getPrincipal();
            userId = currentUser.id.toString(); // Assumes `User` class has a public `id` field of type `UUID`
        } else {
            userId = "Unauthenticated user";
        }

        String action = simplifyAction(request.getRequestURI()); // Simplify for cleaner logs
        String noteId = extractNoteIdFromUri(request.getRequestURI());
    
        securityThreatLogger.logUnauthorizedAccess(userId, action, noteId);

        // Respond with a 403 Forbidden status
        response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access Denied");
    }
    /**
     * Extracts the Note ID from the URI if it's present at the end of the URI.
     * Assumes the URI pattern is /note/{action}/{id}.
     * @param uri The request URI
     * @return The extracted Note ID or "Unknown Note ID" if extraction fails
     */
    private String extractNoteIdFromUri(String uri) {
        String[] segments = uri.split("/");
        return segments.length > 0 ? segments[segments.length - 1] : "Unknown Note ID";
    }

    /**
     * Simplifies action for logging by converting the URI to a keyword.
     */
    private String simplifyAction(String uri) {
        if (uri.contains("/note/edit")) return "EDIT";
        if (uri.contains("/note/delete")) return "DELETE";
        if (uri.contains("/note/view")) return "VIEW";
        if (uri.contains("/note/share")) return "SHARE";
        if (uri.contains("/note/create")) return "CREATE";
        return "UNKNOWN_ACTION";
    }
}