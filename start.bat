@echo off
echo ===================================================
echo 🛡️ Starting PhantomAgent (Backend + Frontend) 🛡️
echo ===================================================

:: Start Backend in a new window
echo [SYSTEM] Launching FastAPI Backend...
start cmd /k "title PhantomAgent Backend && .venv\Scripts\python run.py"

:: Start Frontend in a new window
echo [SYSTEM] Launching React Frontend...
start cmd /k "title PhantomAgent Frontend && cd frontend && npm run dev"

echo.
echo [SUCCESS] Both services launched successfully!
echo   - Backend API: http://localhost:8000
echo   - Frontend:    http://localhost:5173
echo.
echo Press any key to exit this launcher window...
pause > nul
