@echo off
setlocal
cd /d "%~dp0"

set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" (
  echo Couldn't find the C# compiler that comes with Windows.
  echo Turn on ".NET Framework 4.8 Advanced Services" in "Turn Windows features on or off", then try again.
  pause
  exit /b 1
)

echo Building Relay.exe...
"%CSC%" /nologo /target:exe /optimize+ /out:Relay.exe /r:System.Web.Extensions.dll /resource:index.html,Relay.index.html Relay.cs
if errorlevel 1 (
  echo.
  echo Build failed. Copy the messages above and send them to Claude.
  pause
  exit /b 1
)

echo.
echo Done. Double-click Relay.exe to start it.
pause
