@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if not errorlevel 1 (
  py -3 -c "import sys; sys.exit(sys.version_info < (3,12))" >nul 2>nul
  if not errorlevel 1 (
    py -3 -m atlas.server %*
    goto finish
  )
)
where python >nul 2>nul
if not errorlevel 1 (
  python -c "import sys; sys.exit(sys.version_info < (3,12))" >nul 2>nul
  if not errorlevel 1 (
    python -m atlas.server %*
    goto finish
  )
)
if exist "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" (
  "%USERPROFILE%\.cache\codex-runtimes\codex-primary-runtime\dependencies\python\python.exe" -m atlas.server %*
  goto finish
)
echo Python 3.12 or newer is required. Install Python, then run Start.cmd again.
:finish
pause
