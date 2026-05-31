@echo off
:: build.bat — build locker.exe locally with PyInstaller and print its SHA-256.
:: Requires: pip install pyinstaller cryptography argon2-cffi psutil

echo Installing build dependencies...
python -m pip install --upgrade pyinstaller cryptography argon2-cffi psutil || goto :error

echo.
echo Building locker.exe...
pyinstaller --onefile --noconsole --icon locker.ico --name locker ^
    --add-data "locker.ico;." locker.py || goto :error

echo.
echo Build complete: dist\locker.exe
echo.
echo SHA-256 checksum (publish this on the release page):
powershell -NoProfile -Command "(Get-FileHash 'dist\locker.exe' -Algorithm SHA256).Hash"
goto :eof

:error
echo.
echo Build failed.
exit /b 1
