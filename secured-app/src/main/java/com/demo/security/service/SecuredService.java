package com.demo.security.service;

import com.demo.security.model.Comment;
import com.demo.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.util.ArrayList;
import java.util.List;

/**
 * ✅ SECURED SERVICE - DEMONSTRATES SECURITY BEST PRACTICES
 *
 * Key security improvements:
 * 1. Parameterized queries prevent SQL injection
 * 2. Sensitive data is never returned in API responses
 * 3. Input validation at service layer (defense in depth)
 */
@Service
public class SecuredService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private List<Comment> comments = new ArrayList<>();

    @PostConstruct
    public void init() {
        // Create tables with proper schema
        jdbcTemplate.execute(
            "CREATE TABLE IF NOT EXISTS users (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "username VARCHAR(255) NOT NULL, " +
            "email VARCHAR(255) NOT NULL, " +
            "password_hash VARCHAR(255) NOT NULL, " +  // Store hash, not plaintext!
            "role VARCHAR(50) NOT NULL, " +
            "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP" +
            ")"
        );

        // Insert sample data (with hashed passwords in real scenario)
        jdbcTemplate.execute(
            "INSERT INTO users (username, email, password_hash, role) VALUES " +
            "('admin', 'admin@company.com', '$2a$10$xxxHASHEDxxx', 'ADMIN'), " +
            "('john_doe', 'john@example.com', '$2a$10$xxxHASHEDxxx', 'USER'), " +
            "('jane_smith', 'jane@example.com', '$2a$10$xxxHASHEDxxx', 'USER')"
        );

        comments.add(new Comment("System", "Welcome to the secured comments section!"));

        System.out.println("✅ Secured database initialized");
    }

    /**
     * ✅ SECURE: Uses PreparedStatement with parameterized queries
     *
     * The '?' placeholder ensures user input is treated as data, not SQL code.
     * This completely prevents SQL injection attacks.
     */
    public List<User> searchUserSecured(String username) {
        // SECURE: Parameterized query with placeholder
        String sql = "SELECT id, username, email, role FROM users WHERE username LIKE ?";

        System.out.println("✅ Executing secured query with parameter: " + username);

        return jdbcTemplate.query(
            sql,
            new Object[]{"%" + username + "%"},  // Parameter binding
            (rs, rowNum) -> {
                User user = new User();
                user.setId(rs.getInt("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                user.setRole(rs.getString("role"));
                // SECURE: Never return password, credit card, SSN, etc.
                return user;
            }
        );
    }

    /**
     * ✅ SECURE: Get all users without sensitive data
     */
    public List<User> getAllUsers() {
        // Only select non-sensitive columns
        return jdbcTemplate.query(
            "SELECT id, username, email, role FROM users",
            (rs, rowNum) -> {
                User user = new User();
                user.setId(rs.getInt("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                user.setRole(rs.getString("role"));
                return user;
            }
        );
    }

    /**
     * ✅ SECURE: Comments are already HTML-encoded by controller
     */
    public void saveComment(String author, String comment) {
        // Additional validation at service layer (defense in depth)
        if (author != null && comment != null &&
            author.length() <= 50 && comment.length() <= 1000) {
            comments.add(new Comment(author, comment));
        }
    }

    public List<Comment> getAllComments() {
        return new ArrayList<>(comments);
    }
}
