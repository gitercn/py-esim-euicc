@echo off
chcp 65001 >nul

if not exist "%~dp0pysim\osmo-smdpp.py" (
  echo osmo-smdpp.py not found.
  echo Clone pysim into this directory first:
  echo   git clone https://github.com/osmocom/pysim.git
  echo then install its dependencies:
  echo   uv sync --extra smdp
  pause
  exit /b 1
)

cd /d "%~dp0pysim"

rem Apply the Windows path fix if it is not already applied.
git apply --reverse --check "%~dp0patches\osmo-smdpp-windows.patch" >nul 2>&1
if errorlevel 1 (
  git apply "%~dp0patches\osmo-smdpp-windows.patch"
  if errorlevel 1 echo WARNING: could not apply patches\osmo-smdpp-windows.patch
)

echo ============================================
echo   Local SM-DP+ for SGP.26 test profiles
echo   https://testsmdpplus1.example.com:443
echo ============================================
echo.
echo Requires in C:\Windows\System32\drivers\etc\hosts:
echo     127.0.0.1 testsmdpplus1.example.com
echo.
echo Activation code to paste into the LPA:
echo     LPA:1$testsmdpplus1.example.com$TS48V1-A-UNIQUE
echo.
echo Press Ctrl+C to stop the server.
echo.

python osmo-smdpp.py --smdp-address testsmdpplus1.example.com -p 443
pause
