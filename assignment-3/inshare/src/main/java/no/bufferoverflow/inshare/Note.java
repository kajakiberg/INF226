package no.bufferoverflow.inshare;

import org.jsoup.Jsoup;
import org.jsoup.safety.Safelist;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import io.vavr.Tuple2;
import io.vavr.collection.HashMap;
import io.vavr.collection.Map;
import io.vavr.collection.Set;
import io.vavr.collection.HashSet;
import io.ebean.uuidv7.UUIDv7;
import org.springframework.jdbc.core.JdbcTemplate;
import java.time.Instant;

import java.util.UUID;
import java.util.Comparator;
import java.util.EnumSet;

/**
 * Represents a Note in the InShare application.
 * A Note is defined by an ID, name, creation timestamp, content,
 * and a set of permissions for various users.
 */
public final class Note {
    public final UUID id;
    public final User author;
    public final String name;
    public final Instant created;
    public final String content;
    private static final Logger logger = LoggerFactory.getLogger(SQLiteConfig.class);
        /**
     * A map representing the permissions assigned to users.
     * The key is the user ID, and the value is a set of permissions for
     * the user with that ID.
     */
    public final Map<UUID, Role> userRole;


    /**
     * Comparator for comparing notes by their creation date.
     */
    public static final Comparator<Note> byCreationDate = new Comparator<Note> (){

        @Override
        public int compare(Note note0, Note note1) {
            return note0.created.compareTo(note1.created);
        }

    };

    /**
     * Enum representing possible permissions for a note.
     */
    public static enum Permission {
        READ, WRITE, DELETE, SHARE, TRANSFER
    }

    /**
     * 
     * @param id
     * @param author
     * @param name
     * @param created
     * @param content
     * @param userPermissions
     */
    public static enum Role {
        OWNER(EnumSet.of(Permission.READ, Permission.WRITE, Permission.DELETE, Permission.SHARE, Permission.TRANSFER)),
        ADMINISTRATOR(EnumSet.of(Permission.READ, Permission.WRITE, Permission.DELETE, Permission.SHARE)),
        READER(EnumSet.of(Permission.READ)),
        EDITOR(EnumSet.of(Permission.READ, Permission.WRITE));

        EnumSet<Permission> permission;

        Role(EnumSet<Permission> permission) {
            this.permission = permission;
        }

        public EnumSet<Permission> getPermissions() {
            return this.permission;
        }
    }

    /**
     * Constructor for Note which sets all its data.
     *
     * @param id The unique identifier of the note.
     * @param name The name of the note.
     * @param created The timestamp when the note was created.
     * @param content The content of the note.
     * @param userRole The map of user permissions for this note.
     */
    public Note(UUID id, User author, String name, Instant created, String content, Map<UUID, Role> userRole) {
        this.id = id;
        this.name = sanitize(name);
        this.author = author;
        this.created = created;
        this.content = sanitize(content);
        this.userRole = userRole;
    }

    /**
     * Constructs a new Note with a generated ID and current timestamp.
     * The note is created without any permissions.
     *
     * @param name The name of the note.
     * @param content The content of the note.
     */
    public Note(User author, String name, String content) {
        this(UUIDv7.generate()
            , author
            , sanitize(name)
            , Instant.now()
            , sanitize(content)
            , HashMap.empty()
            );
    }

    /**
     * Returns a new Note object with updated name.
     *
     * @param name The new name for the note.
     * @return A new Note instance with the updated name.
     */
    public Note withName(String name) {
        return new Note(this.id, this.author, sanitize(name), this.created, this.content, this.userRole);
    }

    /**
     * Returns a new Note with updated content.
     *
     * @param content The new content for the note.
     * @return A new Note instance with the updated content.
     */
    public Note withContent(String content) {
        return new Note( this.id
                       , this.author
                       , this.name
                       , this.created
                       , sanitize(content)
                       , this.userRole);
    }



    /**
     * Returns a new Note with the updated user permissions.
     *
     * @param userPermissions The new map of user permissions.
     * @return A new Note instance with the updated user permissions.
     */
    public Note withUserRole(Map<UUID, Role> userRole) {
        return new Note(this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userRole);
    }
    /**
     * Returns a new Note with the updated user permissions.
     *
     * @param user The user to whom the permission is being modified.
     * @param permission The permission to be set for this user.
     * @return A new Note instance with the updated permissions for the user.
     */
    public Note withUserRole(User user, Role role) {
        return new Note(this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userRole.put(user.id,role));
    }

    /**
     * Saves the note to the database.
     * Updates the note if it exists, or inserts it as new if it does not exist.
     * The associated permissions are also saved to the database.
     * Remember to call this transactionally, using @Transactional.
     *
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     */
    public void save(JdbcTemplate jdbcTemplate) {
        final String checkNoteExists = "SELECT COUNT(*) FROM Note WHERE id = ?";
        final Integer count = jdbcTemplate.queryForObject(checkNoteExists, Integer.class, id.toString());

        if (count != null && count > 0) {
            // Note exists, update it
            final String updateNote
                = "UPDATE Note SET author = ?, name = ?, content = ? WHERE id = ?";
            jdbcTemplate.update(updateNote, author.id, name, content, id.toString());
        } else {
            // Note does not exist, insert it
            final String insertNote = "INSERT INTO Note (id, author, name, created, content) VALUES (?, ?, ?, ?, ?)";
            jdbcTemplate.update(insertNote, id.toString(), author.id, name, created.toString(), content);
        }
        // Delete existing permissions for this note
        final String deletePermissions = "DELETE FROM NoteUserRole WHERE note = ?";
        jdbcTemplate.update(deletePermissions, id.toString());

        // Insert new permissions
        final String insertRole = "INSERT INTO NoteUserRole (note, user, role) VALUES (?, ?, ?)";
        final String insertPermission = "INSERT OR IGNORE INTO NoteUserPermission (note, user, permission) VALUES (?, ?, ?)";
        for (Tuple2<UUID, Role> entry : userRole) {
            UUID userid = entry._1;
            Role role = entry._2;
            for (Permission permission : role.getPermissions()) {
                jdbcTemplate.update(insertPermission, id.toString(), userid.toString(), permission.toString());
            }
            jdbcTemplate.update(insertRole, id.toString(), userid.toString(), role.toString());
        }
    }

    /**
     * Loads the role for the specified note from the database.
     *
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     * @param noteId The unique identifier of the note.
     * @return A map of user permissions for the note.
     */
    public static Map<UUID, Role> loadUserRoles(JdbcTemplate jdbcTemplate, UUID noteId) {
        final String sql = """
                SELECT user, role
                FROM NoteUserRole
                WHERE note = ?
                """;

        logger.info("Loading role for note:" + noteId.toString());

        return jdbcTemplate.query(sql, (rs) -> {
            Map<UUID, Role> roleMap = HashMap.empty();

            while (rs.next()) {
                UUID userId = UUID.fromString(rs.getString("user"));

                Role role = Role.valueOf(rs.getString("role").toUpperCase());

                roleMap = roleMap.put(userId, role);
            }

            return roleMap;
        }, noteId.toString());
    }

    /**
     * Loads a note from the database along with its permissions.
     *
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     * @param noteId The unique identifier of the note.
     * @return The Note object loaded from the database.
     * @throws IllegalArgumentException If the note is not found in the database.
     */
    public static Note load(JdbcTemplate jdbcTemplate, UUID noteId) {
        final String sql =  """
                              SELECT n.id, n.author, n.name, n.created, n.content, a.username as author_name, a.password AS author_password
                              FROM Note n
                              JOIN USER a ON a.id = n.author
                              WHERE n.id = ?
                            """;

        Map<UUID, Role> role = loadUserRoles(jdbcTemplate, noteId);
        logger.info("Loading note:" + noteId.toString());
        Note note = jdbcTemplate.queryForObject(sql, (rs, rowNum) -> new Note(
                UUID.fromString(rs.getString("id")),
                new User(UUID.fromString(rs.getString("author")), rs.getString("author_name"), rs.getString("author_password")),
                rs.getString("name"),
                Instant.parse(rs.getString("created")),
                rs.getString("content"),
                role
        ), noteId.toString());

        if (note == null) {
            throw new IllegalArgumentException("Note not found.");
        }

        return note;
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