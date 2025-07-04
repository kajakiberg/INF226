package no.bufferoverflow.inshare;

import org.springframework.http.ResponseEntity;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;

/**
 * REST controller responsible for handling user registration requests.
 * It processes incoming registration data, validates it, and saves the new user to the database.
 */
@RestController
@RequestMapping("/register")
public class RegistrationController {

    /** Template for executing SQL queries against the database. */
    private final JdbcTemplate jdbcTemplate;
    /** Password encoder for hashing passwords*/
    private final PasswordEncoder passwordEncoder;

    /**
     * Data Transfer Object (DTO) for capturing user registration details.
     * This class is used to bind form data to a Java object.
     */
    public class UserRegistrationDto {
        public String username;
        public String password;
    
        public UserRegistrationDto() {}

        public String getUsername() {
            return username;
        }
    
        public void setUsername(String username) {
            this.username = username;
        }
    
        public String getPassword() {
            return password;
        }
    
        public void setPassword(String password) {
            this.password = password;
        }
    }
    /**
     * Response object returned after processing a registration request.
     * It contains the status of the registration and a message.
     */
    public class RegistrationResponse {
        public boolean success;
        public String message;
        public RegistrationResponse(boolean success,String message) {
            this.success = success;
            this.message = message;
        }
        public void setSuccess(boolean success) {
            this.success = success;
        }
        public void setMessage(String message) {
            this.message = message;
        }
    }

    public RegistrationController(JdbcTemplate jdbcTemplate, PasswordEncoder passwordEncoder) {
        this.jdbcTemplate = jdbcTemplate;
        this.passwordEncoder = passwordEncoder;
    }

    /**
     * Handles POST requests to "/register" endpoint, registering a new
     * user in the system.
     * The registration is performed in a transactional context, to ensure
     * atomicity of this operation.
     *
     * @param registrationDto the DTO containing the username and password of the user.
     * @return a {@link ResponseEntity} containing a {@link RegistrationResponse} indicating the result.
     */
    @PostMapping(consumes = "application/x-www-form-urlencoded")
    @Transactional
    public ResponseEntity<RegistrationResponse> register(@ModelAttribute UserRegistrationDto registrationDto) {
        // Validate username (5-20 characters, alphanumeric with underscores allowed)
        if (registrationDto.username == null || !registrationDto.username.matches("[a-zA-Z0-9_]{5,20}")) {
            return ResponseEntity.ok(new RegistrationResponse(false, "Invalid username"));
        }

        // Validate password (at least 8 characters, including uppercase, lowercase, digit and special character)
        if (registrationDto.password == null || !registrationDto.password.matches("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,}$")) {
            return ResponseEntity.ok(new RegistrationResponse(false, "Invalid password.\nPassword must be at least 8 characters, include uppercase, lowercase, digit, and special character."));
        }
        
        // Check if username already exists
        String sql = "SELECT COUNT(*) FROM User WHERE username = ?";
        Integer count = jdbcTemplate.queryForObject(sql, Integer.class, registrationDto.username);
        if (count != null && count > 0) {
            return ResponseEntity.ok(new RegistrationResponse(false, "Username already taken!"));
        }

        // Encode the password
        String hashedPassword = passwordEncoder.encode(registrationDto.password);
        
        new User(registrationDto.username,hashedPassword).save(jdbcTemplate);
        
        return ResponseEntity.ok(new RegistrationResponse(true, "Registration successful!"));
    }
}
