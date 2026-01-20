package com.demo.security.service;

import com.demo.security.model.Comment;
import com.demo.security.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import javax.annotation.PostConstruct;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * ⚠️ VULNERABLE SERVICE - FOR EDUCATIONAL PURPOSES ONLY
 */
@Service
public class VulnerableService {

    @Autowired
    private JdbcTemplate jdbcTemplate;

    private List<Comment> comments = new ArrayList<>();

    @PostConstruct
    public void init() {
        // Create tables
        jdbcTemplate.execute(
            "CREATE TABLE IF NOT EXISTS users (" +
            "id INT AUTO_INCREMENT PRIMARY KEY, " +
            "username VARCHAR(255), " +
            "email VARCHAR(255), " +
            "password VARCHAR(255), " +
            "role VARCHAR(50), " +
            "credit_card VARCHAR(20), " +
            "ssn VARCHAR(15)" +
            ")"
        );

        // Insert sample data (with sensitive information for demo purposes)
        jdbcTemplate.execute(
            "INSERT INTO users (username, email, password, role, credit_card, ssn) VALUES " +
            "('admin', 'admin@company.com', 'admin123', 'ADMIN', '4111-1111-1111-1111', '123-45-6789'), " +
            "('john_doe', 'john@example.com', 'password123', 'USER', '4222-2222-2222-2222', '987-65-4321'), " +
            "('jane_smith', 'jane@example.com', 'jane2024!', 'USER', '4333-3333-3333-3333', '456-78-9012'), " +
            "('bob_wilson', 'bob@company.com', 'bob_secure', 'MANAGER', '4444-4444-4444-4444', '789-01-2345'), " +
            "('alice_johnson', 'alice@example.com', 'alice#pass', 'USER', '4555-5555-5555-5555', '012-34-5678')"
        );

        // Add some sample comments
        comments.add(new Comment("John", "Great application!"));
        comments.add(new Comment("Jane", "Love the features."));

        System.out.println("✓ Database initialized with sample data");
    }

    /**
     * ⚠️ VULNERABLE: SQL Injection
     * Uses string concatenation instead of prepared statements
     */
    public List<User> searchUserVulnerable(String username) throws SQLException {
        List<User> users = new ArrayList<>();

        // VULNERABLE: String concatenation in SQL query
        String sql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";

        System.out.println("⚠️ Executing vulnerable query: " + sql);

        try (Connection conn = jdbcTemplate.getDataSource().getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(sql)) {

            while (rs.next()) {
                User user = new User();
                user.setId(rs.getInt("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                user.setPassword(rs.getString("password"));
                user.setRole(rs.getString("role"));
                user.setCreditCard(rs.getString("credit_card"));
                user.setSsn(rs.getString("ssn"));
                users.add(user);
            }
        }

        return users;
    }

    /**
     * SAFE: Using prepared statement (for comparison)
     */
    public List<User> searchUserSafe(String username) {
        String sql = "SELECT * FROM users WHERE username LIKE ?";
        return jdbcTemplate.query(sql, new Object[]{"%" + username + "%"},
            (rs, rowNum) -> {
                User user = new User();
                user.setId(rs.getInt("id"));
                user.setUsername(rs.getString("username"));
                user.setEmail(rs.getString("email"));
                user.setRole(rs.getString("role"));
                // Don't return sensitive data
                return user;
            }
        );
    }

    public List<User> getAllUsers() {
        return jdbcTemplate.query("SELECT id, username, email, role FROM users",
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

    public void saveComment(String author, String comment) {
        comments.add(new Comment(author, comment));
    }

    public List<Comment> getAllComments() {
        return new ArrayList<>(comments);
    }
}
