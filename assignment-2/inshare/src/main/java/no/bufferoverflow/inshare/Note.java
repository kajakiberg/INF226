package no.bufferoverflow.inshare;

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
    public final Map<UUID, Set<Permission>> userPermissions;


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
        READ, WRITE, DELETE
    }

    /**
     * Constructor for Note which sets all its data.
     *
     * @param id The unique identifier of the note.
     * @param name The name of the note.
     * @param created The timestamp when the note was created.
     * @param content The content of the note.
     * @param userPermissions The map of user permissions for this note.
     */
    public Note(UUID id, User author, String name, Instant created, String content, Map<UUID, Set<Permission>> userPermissions) {
        this.id = id;
        this.name = name;
        this.author = author;
        this.created = created;
        this.content = content;
        this.userPermissions = userPermissions;
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
            , name
            , Instant.now()
            , content
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
        return new Note(this.id, this.author, name, this.created, this.content, this.userPermissions);
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
                       , content
                       , this.userPermissions);
    }



    /**
     * Returns a new Note with the updated user permissions.
     *
     * @param userPermissions The new map of user permissions.
     * @return A new Note instance with the updated user permissions.
     */
    public Note withUserPermissions(Map<UUID, Set<Permission>> userPermissions) {
        return new Note(this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userPermissions);
    }
    /**
     * Returns a new Note with the updated user permissions.
     *
     * @param user The user to whom the permission is being modified.
     * @param permission The permission to be set for this user.
     * @return A new Note instance with the updated permissions for the user.
     */
    public Note withUserPermissions(User user, Set<Permission> permissions) {
        return new Note(this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userPermissions.put(user.id,permissions));
    }
    
    /**
     * Returns a new Note with an additional permission for the specified user.
     *
     * @param user The user to whom the permission is being added.
     * @param permission The permission to be added.
     * @return A new Note instance with the updated permissions for the user.
     */
    public Note withUserPermission(User user, Permission permission) {
        final Set<Permission> oldperms
            = userPermissions.get(user.id).getOrElse(HashSet.of());
        final Set<Permission> newperms
            = oldperms.add(permission);
        return new Note( this.id
                       , this.author
                       , this.name
                       , this.created
                       , this.content
                       , userPermissions.put(user.id,newperms));
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
        final String deletePermissions = "DELETE FROM NoteUserPermission WHERE note = ?";
        jdbcTemplate.update(deletePermissions, id.toString());

        // Insert new permissions
        final String insertPermission = "INSERT INTO NoteUserPermission (note, user, permission) VALUES (?, ?, ?)";
        for (Tuple2<UUID, io.vavr.collection.Set<Permission>> entry : userPermissions) {
            UUID userid = entry._1;
            io.vavr.collection.Set<Permission> permissions = entry._2;
            for (Permission permission : permissions) {
                jdbcTemplate.update(insertPermission, id.toString(), userid.toString(), permission.toString());
            }
        }
    }

    /**
     * Loads permissions for the specified note from the database.
     *
     * @param jdbcTemplate The JdbcTemplate to interact with the database.
     * @param noteId The unique identifier of the note.
     * @return A map of user permissions for the note.
     */
    public static Map<UUID, Set<Permission>> loadPermissions(JdbcTemplate jdbcTemplate, UUID noteId) {
        final String sql = """
                SELECT user, permission
                FROM NoteUserPermission
                WHERE note = ?
                """;

        logger.info("Loading permissions for note:" + noteId.toString());

        return jdbcTemplate.query(sql, (rs) -> {
            Map<UUID, Set<Permission>> permissionsMap = HashMap.empty();

            while (rs.next()) {
                UUID userId = UUID.fromString(rs.getString("user"));

                Permission permission = Permission.valueOf(rs.getString("permission").toUpperCase());

                permissionsMap = permissionsMap.put(userId, permissionsMap.get(userId)
                        .map(existingSet -> existingSet.add(permission))
                        .getOrElse(HashSet.of(permission)));
            }

            return permissionsMap;
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

        Map<UUID, Set<Permission>> permissions = loadPermissions(jdbcTemplate, noteId);
        logger.info("Loading note:" + noteId.toString());
        Note note = jdbcTemplate.queryForObject(sql, (rs, rowNum) -> new Note(
                UUID.fromString(rs.getString("id")),
                new User(UUID.fromString(rs.getString("author")), rs.getString("author_name"), rs.getString("author_password")),
                rs.getString("name"),
                Instant.parse(rs.getString("created")),
                rs.getString("content"),
                permissions
        ), noteId.toString());

        if (note == null) {
            throw new IllegalArgumentException("Note not found.");
        }

        return note;
    }
}