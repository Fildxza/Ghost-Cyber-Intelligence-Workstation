@echo off
rem Fidx-Ghost one-click launcher (Windows). Installs missing deps, builds the UI on first run, opens the browser, serves.
rem Usage: start.cmd [--no-browser]
setlocal
cd /d "%~dp0"
set "PYTHONPATH=%~dp0backend;%PYTHONPATH%"
set "PYTHONUTF8=1"
if "%GHOST_PORT%"=="" set "GHOST_PORT=8787"

python -c "import flask, httpx, cryptography, click" 2>nul
if errorlevel 1 (
  echo [setup] Installing Python dependencies...
  python -m pip install -r backend\requirements.txt || (echo [error] pip install failed & exit /b 1)
)
if not exist frontend\dist\index.html (
  echo [setup] Building the web UI ^(first run, needs Node 20+^)...
  pushd frontend
  call npm install --no-audit --no-fund || (popd & echo [error] npm install failed & exit /b 1)
  call npm run build || (popd & echo [error] UI build failed & exit /b 1)
  popd
)
if /i not "%~1"=="--no-browser" start "" "http://127.0.0.1:%GHOST_PORT%"
echo [run] Fidx-Ghost on http://127.0.0.1:%GHOST_PORT%  ^(Ctrl+C to stop^)
python -m ghost serve --port %GHOST_PORT%
