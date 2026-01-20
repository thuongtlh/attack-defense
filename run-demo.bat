@echo off
echo ============================================================
echo    AI-POWERED ATTACK/DEFENSE SECURITY DEMO
echo    FOR EDUCATIONAL PURPOSES ONLY
echo ============================================================
echo.

:menu
echo Select an option:
echo.
echo [1] Start Vulnerable Application (Java)
echo [2] Run AI Attack System (Python)
echo [3] Manual Attack Tests (curl commands)
echo [4] View Security Report
echo [5] Exit
echo.
set /p choice="Enter your choice (1-5): "

if "%choice%"=="1" goto start_app
if "%choice%"=="2" goto run_attack
if "%choice%"=="3" goto manual_tests
if "%choice%"=="4" goto view_report
if "%choice%"=="5" goto end

echo Invalid choice. Please try again.
goto menu

:start_app
echo.
echo Starting Vulnerable Application...
echo Navigate to http://localhost:8080 in your browser
echo Press Ctrl+C to stop the application
echo.
cd vulnerable-app
call mvn spring-boot:run
goto menu

:run_attack
echo.
echo Running AI Attack System...
echo Make sure the vulnerable app is running first!
echo.
cd ai-attack-system
if not exist venv (
    echo Creating virtual environment...
    python -m venv venv
)
call venv\Scripts\activate
pip install -r requirements.txt -q
python ai_attacker.py --target http://localhost:8080 --output security_report.txt
echo.
echo Report saved to: ai-attack-system\security_report.txt
pause
goto menu

:manual_tests
echo.
echo ============================================================
echo    MANUAL ATTACK TESTS
echo ============================================================
echo.
echo 1. SQL Injection Test:
echo    curl "http://localhost:8080/api/users/search?username=' OR '1'='1' --"
echo.
echo 2. XSS Test:
echo    curl -X POST "http://localhost:8080/api/comments?author=Test&comment=<script>alert('XSS')</script>"
echo.
echo 3. Command Injection Test (Windows):
echo    curl "http://localhost:8080/api/ping?host=127.0.0.1 && whoami"
echo.
echo 4. Path Traversal Test:
echo    curl "http://localhost:8080/api/files?filename=..\..\pom.xml"
echo.
pause
goto menu

:view_report
echo.
if exist ai-attack-system\security_report.txt (
    type ai-attack-system\security_report.txt | more
) else (
    echo No report found. Run the AI Attack System first.
)
pause
goto menu

:end
echo.
echo Thank you for using the Security Demo!
echo Remember: Only test systems you have permission to test!
exit /b 0
