@echo off
:: build.bat — build locker.exe locally with Nuitka and print its SHA-256.
::
:: Nuitka compiles Python to C, which produces a real machine-code binary that
:: triggers far fewer antivirus false-positives than a PyInstaller bundle.
:: (Note: it does NOT remove the Windows SmartScreen warning — only code
:: signing does that.)
::
:: Requirements: pip install nuitka cryptography argon2-cffi psutil
:: On first run Nuitka downloads a MinGW C toolchain automatically.

echo Installing build dependencies...
python -m pip install --upgrade nuitka cryptography argon2-cffi psutil || goto :error

echo.
echo Building locker.exe with Nuitka (this can take a few minutes)...
python -m nuitka ^
    --onefile ^
    --windows-console-mode=disable ^
    --enable-plugin=tk-inter ^
    --windows-icon-from-ico=locker.ico ^
    --include-data-files=locker.ico=locker.ico ^
    --company-name=FolderLocker ^
    --product-name=FolderLocker ^
    --file-version=1.0.1 ^
    --product-version=1.0.1 ^
    --file-description="FolderLocker - encrypt and lock folders" ^
    --assume-yes-for-downloads ^
    --output-filename=locker.exe ^
    --output-dir=dist ^
    locker.py || goto :error

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
