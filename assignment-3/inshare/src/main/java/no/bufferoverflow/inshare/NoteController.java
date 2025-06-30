package no.bufferoverflow.inshare;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import io.vavr.collection.HashMap;
import io.vavr.collection.HashSet;
import java.util.List;
import io.vavr.collection.Map;
import io.vavr.collection.Set;
import io.vavr.control.Option;
import no.bufferoverflow.inshare.Note.Permission;
import no.bufferoverflow.inshare.Note.Role;
import no.bufferoverflow.inshare.loggers.NoteActionLogger;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.UUID;

/**
 * Controller for handling note operations, such as viewing, editing,
 * creating, deleting, and sharing notes. It integrates with the database using
 * {@link JdbcTemplate} and manages user-specific permissions.
 */
@Controller
@RequestMapping("/note")
public class NoteController {


    /** Template for executing SQL queries against the database. */
    private final JdbcTemplate jdbcTemplate;
    /** Service for loading user details and authentication. */
    private final InShareUserDetailService userDetailService;
    @Autowired
    private NoteActionLogger noteActionLogger;

    public NoteController(JdbcTemplate jdbcTemplate, InShareUserDetailService userDetailService) {
        this.jdbcTemplate = jdbcTemplate;
        this.userDetailService = userDetailService;
    }

    /**
     * Show the view page for a note
     *
     * @param id the unique identifier of the note.
     * @param model the UI model which will be passed to the template. Modified by this method.
     * @return the name of the template ("viewNote")
     */
    @GetMapping("/view/{id}")
    public String showViewForm(@PathVariable("id") UUID id, Model model) {
        Note note = Note.load(jdbcTemplate, id);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication != null && authentication.isAuthenticated() && (authentication.getPrincipal() instanceof User)) {
            final User user = (User) authentication.getPrincipal();

            // Check if the user has READ permission
            Option<Role> userRoleOption = note.userRole.get(user.id);
            if (userRoleOption.isDefined() && userRoleOption.get().getPermissions().contains(Note.Permission.READ)) {
                model.addAttribute("note", note);
                return "viewNote";
            } else {
                throw new AccessDeniedException("User does not have permission to view this note");
            }
        }
        return "redirect:/";
    }

    /**
     * Displays the form to edit an existing note.
     *
     * @param id the unique identifier of the note.
     * @param model the UI model which will be passed to the template. Modified by this method.
     * @return the view name for editing the note, "editNote"
     */
    @GetMapping("/edit/{id}")
    public String showEditForm(@PathVariable("id") UUID id, Model model) {
        Note note = Note.load(jdbcTemplate, id);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null && authentication.isAuthenticated() && (authentication.getPrincipal() instanceof User)) {
            final User user = (User) authentication.getPrincipal();
            if (note.userRole.get(user.id).get().getPermissions().contains(Note.Permission.WRITE)) {
                model.addAttribute("note", note);
                return "editNote";
            } 
        }
        return "redirect:/";
    }

    /**
     * Handles the submission of the edit form and updates the note in the database.
     * This operation is transactional to ensure the note is updated atomically.
     *
     * @param id the unique identifier of the note to be updated.
     * @param name the new name for the note.
     * @param content the new content for the note.
     * @return a redirect to the dashboard after the update.
     */
    @PostMapping("/edit/{id}")
    @Transactional
    public String updateNote(@PathVariable("id") UUID id,
                             @RequestParam("name") String name,
                             @RequestParam("content") String content) {
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication.getPrincipal() instanceof User)) {
            throw new AccessDeniedException("User is not authenticated");
        }
        User currentUser = (User) authentication.getPrincipal();
        
        Note note = Note.load(jdbcTemplate, id);
        if (!note.userRole.get(currentUser.id).get().getPermissions().contains(Note.Permission.WRITE)) {
            throw new AccessDeniedException("User does not have permission to edit this note");
        }
        // Sanitize name and content
        name = sanitize(name);
        content = sanitize(content);
        note = note.withName(name).withContent(content);
        note.save(jdbcTemplate);
        noteActionLogger.logEditNote(currentUser.id.toString(), note.id.toString()); // Log the note edit
        return "redirect:/"; // Redirect to dashboard after update
    }


    /**
     * Handles the creation of a new note and assigns default permissions to the
     * authenticated user. This operation is transactional to ensure the note
     * creation and permission assignment are atomic.
     *
     * @param name the name of the new note.
     * @param content the content of the new note.
     * @return a redirect to the edit view of the newly created note.
     */
    @PostMapping("/create")
    @Transactional
    public String createNote(@RequestParam("name") String name,
                             @RequestParam("content") String content) {



        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();

        if (authentication != null && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
            final User user = (User)authentication.getPrincipal();
            final String sanitizedName = sanitize(name);
            final String sanitizedContent = sanitize(content);
            final Note newNote = new Note(user, sanitizedName, sanitizedContent)
                                .withUserRole(user, Note.Role.OWNER);
            newNote.save(jdbcTemplate);
            noteActionLogger.logCreateNote(user.id.toString(), newNote.id.toString()); // Log the note creation
            return "redirect:/note/edit/" + newNote.id.toString();
        }
        return "redirect:/";
    }

    
    /**
     * Deletes the specified note if the authenticated user has the DELETE permission.
     * This operation is transactional to ensure the note
     * deletion is performed atomically.
     *
     * @param id the unique identifier of the note to be deleted.
     * @return a redirect to the dashboard after deletion.
     */
    @PostMapping("/delete/{id}")
    @Transactional
    public String deleteNote(@PathVariable("id") UUID id) {
        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();

        if ( authentication != null
                && authentication.isAuthenticated()
                && (authentication.getPrincipal() instanceof User)) {
            final User user = (User)authentication.getPrincipal();
            Note note = Note.load(jdbcTemplate, id);

            if    (note.userRole.get(user.id).isDefined() && note.userRole.get(user.id).get().getPermissions().contains(Note.Permission.DELETE)) {
                final String deleteNote = "DELETE FROM Note WHERE id = ?";
                jdbcTemplate.update(deleteNote, note.id.toString());
                noteActionLogger.logDeleteNote(user.id.toString(), note.id.toString()); // Log the note deletion
            }
        }
        return "redirect:/";
    }


    /**
     * Displays the form to share a note with another user.
     *
     * @param id the unique identifier of the note.
     * @param model the model to which the note is added.
     * @return the view name for sharing the note.
     */
    @GetMapping("/share/{id}")
    public String showShareForm(@PathVariable("id") UUID id, Model model) {
        final Authentication authentication
            = SecurityContextHolder.getContext()
                                   .getAuthentication();
        final User user = (User) authentication.getPrincipal();
        Note note = Note.load(jdbcTemplate, id);

        if (note.userRole.get(user.id).get().getPermissions().contains(Note.Permission.SHARE)) {
            model.addAttribute("note", note);
            model.addAttribute("emptyset", HashSet.of());
            model.addAttribute("userid", user.id);
            model.addAttribute("transfer", Permission.TRANSFER);
            return "shareNote";
        }
        return "redirect:/";
    }

    /**
     * Retrieves the permissions associated with the specified note for the
     * authenticated user.
     *
     * @param id the unique identifier of the note.
     * @return a map containing the permissions of the authenticated user for the note.
     */
    @GetMapping("/permissions/{id}")
    @ResponseBody
    public Map<String, Object> getNoteRoles(@PathVariable("id") UUID id) {
        Note note = Note.load(jdbcTemplate, id);
        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        User user = (User) authentication.getPrincipal();
        Note.Role role = note.userRole.get(user.id).get();
        return HashMap.of("role", role);
    }

    /**
     * Shares the specified note with another user and grants them the specified permissions.
     * This operation is transactional to ensure the permissions are added atomically.
     *
     * @param noteId the unique identifier of the note to be shared.
     * @param username the username of the user with whom the note is shared.
     * @param permissions the list of permissions to be granted.
     * @return a redirect to the dashboard after sharing.
     * @throws UsernameNotFoundException if the specified user is not found.
     */
    @PostMapping("/share")
    @Transactional
    public String shareNote(
            @RequestParam UUID noteId,
            @RequestParam String username,
            @RequestParam Note.Role role) {

        final Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication.getPrincipal() instanceof User)) {
            throw new AccessDeniedException("User is not authenticated");
        }
        User currentUser = (User) authentication.getPrincipal();

        // Load the note
        Note note = Note.load(jdbcTemplate, noteId);

        if (!note.userRole.get(currentUser.id).get().getPermissions().contains(Note.Permission.SHARE)) {
            throw new AccessDeniedException("User does not have permission to share this note");
        }

    // Ensure only the current OWNER can transfer ownership, and the new role is OWNER
    if (role == Role.OWNER) {
        if (!note.userRole.get(currentUser.id).get().getPermissions().contains(Note.Permission.TRANSFER)) {
            throw new AccessDeniedException("Only the owner can transfer ownership of the note");
        }
        
        // Load the user to whom ownership is being transferred
        User userToAssign = (User) userDetailService.loadUserByUsername(username);
        if (userToAssign == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }

        // Demote the current owner to ADMINISTRATOR
        note = note.withUserRole(currentUser, Role.ADMINISTRATOR);

        // Assign the OWNER role to the new user
        note = note.withUserRole(userToAssign, Role.OWNER);

        note.save(jdbcTemplate);
        noteActionLogger.logTransferOwnership(currentUser.id.toString(), note.id.toString(), userToAssign.id.toString()); // Log the ownership transfer
        return "redirect:/";
    }

        // If assigning a role other than OWNER, proceed as normal
        User userToAssign = (User) userDetailService.loadUserByUsername(username);
        if (userToAssign == null) {
            throw new UsernameNotFoundException("User not found: " + username);
        }
        note = note.withUserRole(userToAssign, role);
        note.save(jdbcTemplate);
        noteActionLogger.logShareNote(currentUser.id.toString(), note.id.toString(), userToAssign.id.toString()); // Log the note share

        return "redirect:/";
    }

    /**
     * Sanitize input to prevent XSS attacks, allowing only essential Quill editor tags and attributes.
     * @param input The input string to sanitize.
     * @return The sanitized string with safeHTML tags.
     */
    private static String sanitize(String input) {
        Safelist inshareSafelist = Safelist.basic()
            .addTags("span", "a") // Allow <span> for text styling and <a> for hyperlinks.
            .addAttributes("a", "href", "target") // Allow links with href for URLs and target to open in a new tab.
            .addAttributes("span", "class", "style") // Allow class and style attributes on <span> to support font sizes and styles.
            .addProtocols("a", "href", "http", "https"); // Restrict <a> href to only http and https protocols for safety.
        return Jsoup.clean(input, inshareSafelist); 
    }
}
