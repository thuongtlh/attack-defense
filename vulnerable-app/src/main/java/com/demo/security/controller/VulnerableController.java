package com.demo.security.controller;

import com.demo.security.model.User;
import com.demo.security.service.VulnerableService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * ⚠️ VULNERABLE CONTROLLER - FOR EDUCATIONAL PURPOSES ONLY
 *
 * This controller contains multiple security vulnerabilities:
 * 1. SQL Injection in user search
 * 2. XSS in comment display
 * 3. Command Injection in ping utility
 * 4. Path Traversal in file reading
 * 5. Insecure Deserialization
 */
@Controller
public class VulnerableController {

    @Autowired
    private VulnerableService vulnerableService;

    @GetMapping("/")
    public String home(Model model) {
        model.addAttribute("message", "Welcome to the Vulnerable Demo Application");
        return "index";
    }

    // ============================================================
    // VULNERABILITY #1: SQL INJECTION
    // ============================================================
    /**
     * ⚠️ VULNERABLE: Direct string concatenation in SQL query
     * Attack example: username = ' OR '1'='1' --
     */
    @GetMapping("/api/users/search")
    @ResponseBody
    public ResponseEntity<?> searchUser(@RequestParam String username) {
        try {
            List<User> users = vulnerableService.searchUserVulnerable(username);
            return ResponseEntity.ok(users);
        } catch (Exception e) {
            Map<String, String> error = new HashMap<>();
            error.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(error);
        }
    }

    @GetMapping("/users")
    public String usersPage(Model model) {
        model.addAttribute("users", vulnerableService.getAllUsers());
        return "users";
    }

    // ============================================================
    // VULNERABILITY #2: CROSS-SITE SCRIPTING (XSS)
    // ============================================================
    /**
     * ⚠️ VULNERABLE: User input directly rendered without escaping
     * Attack example: comment = <script>alert('XSS')</script>
     */
    @PostMapping("/api/comments")
    @ResponseBody
    public ResponseEntity<?> addComment(@RequestParam String comment,
                                         @RequestParam String author) {
        // Vulnerable: storing and returning unsanitized input
        Map<String, String> response = new HashMap<>();
        response.put("comment", comment);  // Will be rendered as-is (XSS!)
        response.put("author", author);
        response.put("status", "Comment added successfully");
        vulnerableService.saveComment(author, comment);
        return ResponseEntity.ok(response);
    }

    @GetMapping("/comments")
    public String commentsPage(Model model) {
        model.addAttribute("comments", vulnerableService.getAllComments());
        return "comments";
    }

    // ============================================================
    // VULNERABILITY #3: COMMAND INJECTION
    // ============================================================
    /**
     * ⚠️ VULNERABLE: User input passed directly to system command
     * Attack example: host = 127.0.0.1; cat /etc/passwd
     *                 host = 127.0.0.1 && dir (Windows)
     */
    @GetMapping("/api/ping")
    @ResponseBody
    public ResponseEntity<?> pingHost(@RequestParam String host) {
        Map<String, Object> response = new HashMap<>();
        try {
            // VULNERABLE: Direct command execution with user input through shell
            // This is intentionally vulnerable for educational demonstration!
            String os = System.getProperty("os.name").toLowerCase();
            String[] command;

            if (os.contains("win")) {
                // Windows: Execute through cmd.exe to enable shell operators (&&, |, etc.)
                // This makes command injection possible!
                command = new String[]{"cmd.exe", "/c", "ping -n 1 " + host};
            } else {
                // Linux/Mac: Execute through sh to enable shell operators (;, |, &&, etc.)
                command = new String[]{"/bin/sh", "-c", "ping -c 1 " + host};
            }

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.redirectErrorStream(true);  // Merge stderr into stdout
            Process process = pb.start();

            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );

            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }

            process.waitFor();

            response.put("command", String.join(" ", command));
            response.put("output", output.toString());
            response.put("exitCode", process.exitValue());

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/network")
    public String networkPage() {
        return "network";
    }

    // ============================================================
    // VULNERABILITY #4: PATH TRAVERSAL
    // ============================================================
    /**
     * ⚠️ VULNERABLE: No validation on file path
     * Attack example: filename = ../../../etc/passwd
     *                 filename = ..\..\..\..\windows\system32\config\sam
     */
    @GetMapping("/api/files")
    @ResponseBody
    public ResponseEntity<?> readFile(@RequestParam String filename) {
        Map<String, Object> response = new HashMap<>();
        try {
            // VULNERABLE: No path validation
            String basePath = System.getProperty("user.dir") + "/uploads/";
            String filePath = basePath + filename;

            String content = new String(Files.readAllBytes(Paths.get(filePath)));

            response.put("filename", filename);
            response.put("content", content);
            response.put("path", filePath);

            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("error", "File not found: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @GetMapping("/files")
    public String filesPage() {
        return "files";
    }

    // ============================================================
    // VULNERABILITY #5: INSECURE DESERIALIZATION
    // ============================================================
    /**
     * ⚠️ VULNERABLE: Deserializing untrusted data
     * Attack: Crafted serialized object to execute arbitrary code
     */
    @PostMapping("/api/deserialize")
    @ResponseBody
    public ResponseEntity<?> deserializeObject(@RequestBody byte[] data) {
        Map<String, Object> response = new HashMap<>();
        try {
            // VULNERABLE: Deserializing untrusted input
            ByteArrayInputStream bis = new ByteArrayInputStream(data);
            ObjectInputStream ois = new ObjectInputStream(bis);
            Object obj = ois.readObject();  // Dangerous!
            ois.close();

            response.put("object", obj.toString());
            response.put("class", obj.getClass().getName());
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            response.put("error", e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    // ============================================================
    // API INFO ENDPOINT
    // ============================================================
    @GetMapping("/api/info")
    @ResponseBody
    public ResponseEntity<?> getApiInfo() {
        Map<String, Object> info = new HashMap<>();
        info.put("application", "Vulnerable Demo App");
        info.put("version", "1.0.0");
        info.put("endpoints", new String[]{
            "GET /api/users/search?username=xxx - Search users (SQL Injection)",
            "POST /api/comments?comment=xxx&author=xxx - Add comment (XSS)",
            "GET /api/ping?host=xxx - Ping host (Command Injection)",
            "GET /api/files?filename=xxx - Read file (Path Traversal)",
            "POST /api/deserialize - Deserialize object (Insecure Deserialization)"
        });
        info.put("warning", "This application is intentionally vulnerable for training purposes!");
        return ResponseEntity.ok(info);
    }
}
