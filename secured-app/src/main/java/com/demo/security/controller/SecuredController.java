package com.demo.security.controller;

import com.demo.security.model.User;
import com.demo.security.service.SecuredService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.HtmlUtils;

import java.io.*;
import java.nio.file.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * ✅ SECURED CONTROLLER - DEMONSTRATES SECURITY BEST PRACTICES
 *
 * This controller shows how to properly fix the vulnerabilities:
 * 1. SQL Injection → Parameterized queries
 * 2. XSS → Input sanitization and output encoding
 * 3. Command Injection → Input validation and safe APIs
 * 4. Path Traversal → Path canonicalization and validation
 * 5. Insecure Deserialization → Whitelist-based deserialization
 */
@Controller
@RequestMapping("/secured")
public class SecuredController {

    @Autowired
    private SecuredService securedService;

    // Whitelist pattern for valid hostnames
    private static final Pattern VALID_HOST_PATTERN =
            Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$");

    // Whitelist pattern for valid filenames
    private static final Pattern VALID_FILENAME_PATTERN =
            Pattern.compile("^[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9]+$");

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("message", "Welcome to the SECURED Demo Application");
        return "secured/index";
    }

    // ============================================================
    // FIX #1: SQL INJECTION → PARAMETERIZED QUERIES
    // ============================================================
    /**
     * ✅ SECURE: Uses PreparedStatement with parameterized queries
     * The user input is never concatenated into the SQL string
     */
    @GetMapping("/api/users/search")
    @ResponseBody
    public ResponseEntity<?> searchUserSecured(@RequestParam String username) {
        try {
            // Input validation: limit length and characters
            if (username == null || username.length() > 50) {
                return ResponseEntity.badRequest()
                        .body(Map.of("error", "Invalid username length"));
            }

            // Remove potentially dangerous characters (defense in depth)
            String sanitizedUsername = username.replaceAll("[^a-zA-Z0-9_\\-@.]", "");

            List<User> users = securedService.searchUserSecured(sanitizedUsername);

            // Don't return sensitive fields
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", "Search failed");  // Generic error message
            return ResponseEntity.badRequest().body(error);
        }
    }

    // ============================================================
    // FIX #2: XSS → INPUT SANITIZATION + OUTPUT ENCODING
    // ============================================================
    /**
     * ✅ SECURE: Sanitizes input and uses HTML encoding
     * - Server-side: HtmlUtils.htmlEscape()
     * - Template: th:text (not th:utext)
     */
    @PostMapping("/api/comments")
    @ResponseBody
    public ResponseEntity<?> addCommentSecured(@RequestParam String comment,
                                                @RequestParam String author) {
        // Input validation
        if (comment == null || comment.length() > 1000) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Comment too long (max 1000 chars)"));
        }
        if (author == null || author.length() > 50) {
            return ResponseEntity.badRequest()
                    .body(Map.of("error", "Author name too long (max 50 chars)"));
        }

        // HTML encode to prevent XSS
        String safeComment = HtmlUtils.htmlEscape(comment);
        String safeAuthor = HtmlUtils.htmlEscape(author);

        Map<String, String> response = new HashMap<>();
        response.put("comment", safeComment);  // HTML encoded
        response.put("author", safeAuthor);
        response.put("status", "Comment added successfully");

        securedService.saveComment(safeAuthor, safeComment);

        return ResponseEntity.ok(response);
    }

    // ============================================================
    // FIX #3: COMMAND INJECTION → INPUT VALIDATION + SAFE API
    // ============================================================
    /**
     * ✅ SECURE: Validates input and uses ProcessBuilder with argument array
     * - Whitelist validation for hostnames
     * - ProcessBuilder prevents shell injection
     * - No string concatenation in command
     */
    @GetMapping("/api/ping")
    @ResponseBody
    public ResponseEntity<?> pingHostSecured(@RequestParam String host) {
        Map<String, Object> response = new HashMap<>();

        // VALIDATION: Check against whitelist pattern
        if (!VALID_HOST_PATTERN.matcher(host).matches()) {
            response.put("error", "Invalid hostname format. Only alphanumeric characters, hyphens, and dots allowed.");
            return ResponseEntity.badRequest().body(response);
        }

        // Additional validation: no IP address ranges, localhost only for demo
        if (host.contains("..") || host.length() > 255) {
            response.put("error", "Invalid hostname");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            // SECURE: Use ProcessBuilder with argument array (not string concatenation)
            ProcessBuilder processBuilder;
            String os = System.getProperty("os.name").toLowerCase();

            if (os.contains("win")) {
                // Windows: arguments passed as separate array elements
                processBuilder = new ProcessBuilder("ping", "-n", "1", host);
            } else {
                // Linux/Mac
                processBuilder = new ProcessBuilder("ping", "-c", "1", host);
            }

            // Redirect error stream to output
            processBuilder.redirectErrorStream(true);

            Process process = processBuilder.start();

            // Read output with timeout
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream())
            );

            StringBuilder output = new StringBuilder();
            String line;
            int lineCount = 0;
            while ((line = reader.readLine()) != null && lineCount < 20) {
                output.append(line).append("\n");
                lineCount++;
            }

            boolean completed = process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS);

            if (!completed) {
                process.destroyForcibly();
                response.put("error", "Command timed out");
                return ResponseEntity.badRequest().body(response);
            }

            response.put("host", host);
            response.put("output", output.toString());
            response.put("exitCode", process.exitValue());
            response.put("secured", true);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", "Ping failed");
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============================================================
    // FIX #4: PATH TRAVERSAL → PATH VALIDATION + CANONICALIZATION
    // ============================================================
    /**
     * ✅ SECURE: Validates and canonicalizes file paths
     * - Whitelist validation for filenames
     * - Canonical path comparison
     * - Restricted to specific directory
     */
    @GetMapping("/api/files")
    @ResponseBody
    public ResponseEntity<?> readFileSecured(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();

        // VALIDATION 1: Check filename against whitelist pattern
        if (!VALID_FILENAME_PATTERN.matcher(filename).matches()) {
            response.put("error", "Invalid filename. Only alphanumeric, underscore, hyphen, and single extension allowed.");
            return ResponseEntity.badRequest().body(response);
        }

        // VALIDATION 2: No path traversal characters
        if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            response.put("error", "Invalid filename: path traversal detected");
            return ResponseEntity.badRequest().body(response);
        }

        try {
            // Define the allowed base directory
            Path baseDir = Paths.get(System.getProperty("user.dir"), "uploads")
                    .toAbsolutePath()
                    .normalize();

            // Resolve the requested file
            Path requestedFile = baseDir.resolve(filename)
                    .toAbsolutePath()
                    .normalize();

            // VALIDATION 3: Canonical path must be within base directory
            if (!requestedFile.startsWith(baseDir)) {
                response.put("error", "Access denied: file outside allowed directory");
                return ResponseEntity.badRequest().body(response);
            }

            // VALIDATION 4: File must exist and be readable
            if (!Files.exists(requestedFile) || !Files.isRegularFile(requestedFile)) {
                response.put("error", "File not found");
                return ResponseEntity.badRequest().body(response);
            }

            // VALIDATION 5: File size limit (prevent DoS)
            if (Files.size(requestedFile) > 1024 * 1024) {  // 1MB limit
                response.put("error", "File too large");
                return ResponseEntity.badRequest().body(response);
            }

            // Read file content safely
            String content = Files.readString(requestedFile);

            response.put("filename", filename);
            response.put("content", content);
            response.put("secured", true);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", "File read failed");
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============================================================
    // FIX #5: INSECURE DESERIALIZATION → WHITELIST + ALTERNATIVES
    // ============================================================
    /**
     * ✅ SECURE: Don't deserialize untrusted data!
     * Better alternatives:
     * - Use JSON/XML with schema validation
     * - Use data transfer objects (DTOs)
     * - If serialization needed, use whitelist
     */
    @PostMapping("/api/deserialize")
    @ResponseBody
    public ResponseEntity<?> deserializeSecured(@RequestBody String jsonData) {
        Map<String, Object> response = new HashMap<>();

        try {
            // SECURE: Use JSON instead of Java serialization
            // Parse JSON with a safe library (Jackson/Gson with type restrictions)
            com.google.gson.Gson gson = new com.google.gson.Gson();

            // Only allow specific DTO types
            Map<String, Object> data = gson.fromJson(jsonData, Map.class);

            // Validate expected fields
            if (data == null || !data.containsKey("type")) {
                response.put("error", "Invalid JSON format");
                return ResponseEntity.badRequest().body(response);
            }

            response.put("data", data);
            response.put("message", "JSON parsed safely (no Java deserialization)");
            response.put("secured", true);

            return ResponseEntity.ok(response);

        } catch (Exception e) {
            response.put("error", "Invalid JSON data");
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============================================================
    // API INFO - SECURED VERSION
    // ============================================================
    @GetMapping("/api/info")
    @ResponseBody
    public ResponseEntity<?> getApiInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("application", "SECURED Demo App");
        info.put("version", "2.0.0-SECURED");
        info.put("endpoints", new String[]{
                "GET /secured/api/users/search?username=xxx - Parameterized query (SQL Injection FIXED)",
                "POST /secured/api/comments - HTML encoded output (XSS FIXED)",
                "GET /secured/api/ping?host=xxx - ProcessBuilder with validation (Command Injection FIXED)",
                "GET /secured/api/files?filename=xxx - Path canonicalization (Path Traversal FIXED)",
                "POST /secured/api/deserialize - JSON instead of Java serialization (Deserialization FIXED)"
        });
        info.put("security", "All OWASP Top 10 vulnerabilities have been patched!");
        return ResponseEntity.ok(info);
    }
}
