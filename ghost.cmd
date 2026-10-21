@echo off
rem Fidx-Ghost CLI launcher (Windows). Usage: ghost.cmd status | ghost.cmd case list | ...
set "PYTHONPATH=%~dp0backend;%PYTHONPATH%"
set "PYTHONUTF8=1"
python -m ghost %*
