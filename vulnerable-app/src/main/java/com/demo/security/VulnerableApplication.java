package com.demo.security;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * ⚠️ WARNING: This application is INTENTIONALLY VULNERABLE
 *
 * This is a demonstration application for security training purposes.
 * DO NOT deploy this application in any production environment.
 *
 * Vulnerabilities included:
 * 1. SQL Injection
 * 2. Cross-Site Scripting (XSS)
 * 3. Command Injection
 * 4. Path Traversal
 * 5. Insecure Deserialization
 */
@SpringBootApplication
public class VulnerableApplication {

    public static void main(String[] args) {
        System.out.println("╔════════════════════════════════════════════════════════════╗");
        System.out.println("║  ⚠️  WARNING: VULNERABLE APPLICATION FOR TRAINING ONLY  ⚠️  ║");
        System.out.println("║     DO NOT DEPLOY IN PRODUCTION ENVIRONMENT               ║");
        System.out.println("╚════════════════════════════════════════════════════════════╝");
        SpringApplication.run(VulnerableApplication.class, args);
    }
}
