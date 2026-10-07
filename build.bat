@echo off
rem Kompiliert PingMonitor.exe mit dem in Windows enthaltenen .NET Framework Compiler.
setlocal
cd /d "%~dp0"
set CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe
if not exist "%CSC%" (
  echo csc.exe wurde nicht gefunden. Bitte .NET Framework 4.x installieren.
  pause
  exit /b 1
)
"%CSC%" /nologo /target:winexe /optimize+ /codepage:65001 /out:PingMonitor.exe ^
  /r:System.dll /r:System.Drawing.dll /r:System.Windows.Forms.dll /r:System.ServiceProcess.dll /r:System.Security.dll /resource:macvendors.txt,macvendors.txt PingMonitor.cs
if errorlevel 1 (
  echo.
  echo Fehler beim Kompilieren.
  pause
  exit /b 1
)
echo PingMonitor.exe wurde erstellt.
pause
