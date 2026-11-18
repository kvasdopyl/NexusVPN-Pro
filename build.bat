@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo === NexusVPN Pro: сборка ===
where python >nul 2>nul || (echo Установите Python 3.12 с python.org и отметьте "Add to PATH" & pause & exit /b 1)
python -m venv .venv || goto :err
call .venv\Scripts\activate.bat
python -m pip install -q --upgrade pip
python -m pip install -q -r requirements.txt pyinstaller || goto :err
pyinstaller --noconfirm --clean NexusVPN.spec || goto :err
echo.
echo Готово: "dist\NexusVPN Pro\NexusVPN Pro.exe"
pause
exit /b 0
:err
echo ОШИБКА СБОРКИ
pause
exit /b 1
