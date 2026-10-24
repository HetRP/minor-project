@echo off
REM Real local datasets only. Stop on preparation, smoke, training or evaluation failure.
cd /d "%~dp0.."
python model\run_real_training.py
exit /b %ERRORLEVEL%
