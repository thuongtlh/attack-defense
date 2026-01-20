package com.demo.security.model;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * Comment model for XSS demonstration
 */
public class Comment {
    private String author;
    private String content;
    private String timestamp;

    public Comment(String author, String content) {
        this.author = author;
        this.content = content;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
    }

    public String getAuthor() { return author; }
    public void setAuthor(String author) { this.author = author; }

    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }
}
