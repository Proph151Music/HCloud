@echo off
setlocal enabledelayedexpansion

set SCRIPT_DIR=%~dp0
set LOGFILE="%SCRIPT_DIR%HCloud_launcher.log"

REM Set the current directory to the directory of the batch file
cd /d %~dp0

echo Log file location: %LOGFILE% > %LOGFILE%
echo Starting script... >> %LOGFILE%
echo Starting script...

REM Check if Python is already installed
echo Checking if Python is installed... >> %LOGFILE%
echo Checking if Python is installed...
python --version >> %LOGFILE% 2>>&1
set PYTHON_ERRORLEVEL=%errorlevel%
echo Python command errorlevel: %PYTHON_ERRORLEVEL% >> %LOGFILE%

if "%PYTHON_ERRORLEVEL%"=="0" (
    echo Inside if statement for Python found >> %LOGFILE%
    for /f "tokens=2 delims= " %%A in ('python --version 2^>^&1') do (
        set "PYTHON_VERSION=%%A"
        echo Inside for loop, found Python version %%A >> %LOGFILE%
    )
    echo Python version !PYTHON_VERSION! is already installed. >> %LOGFILE%
    echo Python version !PYTHON_VERSION! is already installed.
    for /f "delims=" %%i in ('powershell -command "(Get-Command python).Path"') do set "PYTHON_DIR=%%~dpi"
    echo Python is located at: !PYTHON_DIR! >> %LOGFILE%

    REM Check for pip installation
    echo Checking if pip is installed... >> %LOGFILE%
    pip --version >> %LOGFILE% 2>>&1
    set PIP_ERRORLEVEL=%errorlevel%
    echo pip command errorlevel: !PIP_ERRORLEVEL! >> %LOGFILE%

    if "!PIP_ERRORLEVEL!"=="0" (
        echo pip found. >> %LOGFILE%
        echo pip is installed. >> %LOGFILE%
        echo pip is installed.

        REM Call function to check and run HCloud
        call :check_and_run_HCloud
    ) else (
        echo pip not found. >> %LOGFILE%
        echo pip is not installed. >> %LOGFILE%
        echo pip is not installed.
    )
) else (
    echo Python not found in PATH, searching all possible locations... >> %LOGFILE%
    echo Python not found in PATH, searching all possible locations...
    call :find_python_in_registry

    if "%PYTHON_FOUND%"=="0" (
        echo After find_python_in_registry, PYTHON_FOUND=%PYTHON_FOUND% >> %LOGFILE%
        call :find_python_in_common_locations

        if "%PYTHON_FOUND%"=="0" (
            echo After find_python_in_common_locations, PYTHON_FOUND=%PYTHON_FOUND% >> %LOGFILE%
            echo Calling install_python because Python was not found. >> %LOGFILE%
            call :install_python
        )
    )
)

goto end

:find_python_in_registry
set PYTHON_FOUND=0
set "REG_PATH=HKLM\SOFTWARE\Python\PythonCore"
echo Querying registry path: %REG_PATH% >> %LOGFILE%

for /f "tokens=*" %%i in ('reg query "%REG_PATH%" /s /v ExecutablePath 2^>nul') do (
    echo Registry line: %%i >> %LOGFILE%
    if "%%i"=="End of search: 0 match(es) found." (
        goto :end_registry_search_no_match
    )
    for /f "tokens=2*" %%j in ("%%i") do (
        if "%%j"=="REG_SZ" (
            set "PYTHON_EXEC=%%k"
            echo Extracted ExecutablePath: !PYTHON_EXEC! >> %LOGFILE%
            set "PYTHON_DIR=!PYTHON_EXEC:\python.exe=!"
            setx PATH "%PYTHON_DIR%;%PYTHON_DIR%\Scripts;%PATH%" >> %LOGFILE% 2>>&1
            echo Python directory set from registry: !PYTHON_DIR! >> %LOGFILE%
            echo Extracted PYTHON_DIR: !PYTHON_DIR! >> %LOGFILE%
            set PYTHON_FOUND=1
            goto :end_registry_search
        )
    )
)

:end_registry_search_no_match
echo No matches found in registry. >> %LOGFILE%
goto :find_python_in_common_locations

:end_registry_search
if %PYTHON_FOUND% equ 1 (
    echo Found Python installation in registry: %PYTHON_DIR% >> %LOGFILE%
    echo Found Python installation in registry: %PYTHON_DIR%
    set PATH=%PYTHON_DIR%;%PYTHON_DIR%\Scripts;%PATH%
    setx PATH "%PATH%" >> %LOGFILE% 2>>&1
    echo Added Python to PATH and continuing to check_python >> %LOGFILE%
    goto check_python
)

:find_python_in_common_locations
set PYTHON_FOUND=0
for %%D in (
    "%LocalAppData%\Programs\Python\Python3*"
    "%ProgramFiles%\Python3*"
    "%ProgramFiles(x86)%\Python3*"
    REM "%LOCALAPPDATA%\Microsoft\WindowsApps"
) do (
    echo Checking %%D for Python... >> %LOGFILE%
    if exist "%%D\python.exe" (
        set "PYTHON_DIR=%%D"
        echo Found Python installation in %%D >> %LOGFILE%
        echo Found Python installation in %%D
        setx PATH "%%D;%%D\Scripts;%PATH%" >> %LOGFILE% 2>>&1
        set PYTHON_FOUND=1
        goto check_python
    )
)

if !PYTHON_FOUND! equ 0 (
    echo No Python installations found in common locations. >> %LOGFILE%
    echo No Python installations found in common locations.
    echo Python is not installed.
    set /p install="Do you want to install Python and pip? (y/n): "
    echo User chose to !install! >> %LOGFILE%
    if /i "!install!"=="y" (
        echo User chose to install >> %LOGFILE%
        call :install_python
    ) else (
        echo Exiting... >> %LOGFILE%
        echo Exiting...
        exit /b
    )
)


:check_python
set PATH=%PYTHON_DIR%;%PYTHON_DIR%\Scripts;%PATH%

python --version >> %LOGFILE% 2>>&1
set CHECK_PYTHON_ERRORLEVEL=%errorlevel%
echo Check Python errorlevel: %CHECK_PYTHON_ERRORLEVEL% >> %LOGFILE%

if "%CHECK_PYTHON_ERRORLEVEL%"=="0" (
    echo Python successfully added to PATH. >> %LOGFILE%
    echo Python successfully added to PATH.
    goto end
) else (
    echo Python was not found even after adding to PATH. >> %LOGFILE%
    echo Python was not found even after adding to PATH.
    exit /b
)

REM Function to check and run HCloud
:check_and_run_HCloud
echo.
set /p run_HCloud="Do you want to run the Hetzner Cloud Management Tool (HCloud)? (y/n): "
if /i "!run_HCloud!"=="y" (
    if not exist "HCloud.py" (
        echo HCloud.py not found in the current directory. Downloading HCloud.py... >> %LOGFILE%
        powershell -Command "Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/Proph151Music/HCloud/main/HCloud.py' -OutFile 'HCloud.py'" >> %LOGFILE% 2>>&1
        if exist "HCloud.py" (
            echo HCloud.py downloaded successfully. >> %LOGFILE%
        ) else (
            echo Failed to download HCloud.py. >> %LOGFILE%
            goto end
        )
    )
    REM Log the directory from where HCloud.py is being launched
    echo Launching HCloud.py from directory: %cd% >> %LOGFILE%
    echo Running HCloud.py... >> %LOGFILE%
    start "" python HCloud.py
    exit
)
goto :eof

REM Function to uninstall Python
:uninstall_python
echo Uninstalling Python... >> %LOGFILE%
echo Uninstalling Python...

REM Get the uninstall strings for all Python components from the registry using PowerShell and execute them
for /f "usebackq tokens=*" %%i in (`powershell -Command "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object { $_.DisplayName -like 'Python *' } | Select-Object -ExpandProperty UninstallString"`) do (
    set "uninstallString=%%i"
    echo Found uninstall string: !uninstallString! >> %LOGFILE%
    if defined uninstallString (
        set "uninstallString=!uninstallString:/I=/X!"
        echo Uninstalling with command: "!uninstallString! /passive /norestart" >> %LOGFILE%
        call !uninstallString! /passive /norestart >> %LOGFILE% 2>>&1
        echo Python uninstallation command executed: !uninstallString! >> %LOGFILE%
    ) else (
        echo No uninstall string found for %%i >> %LOGFILE%
    )
)

REM Check if the uninstallation was successful
for /f "usebackq tokens=*" %%i in (`powershell -Command "Get-ItemProperty -Path HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Where-Object { $_.DisplayName -like 'Python *' } | Select-Object DisplayName"`) do (
    echo Still found an installed Python entry: %%i >> %LOGFILE%
    echo Still found an installed Python entry: %%i
)

echo Python uninstalled. >> %LOGFILE%
goto end

REM Proceed with installation
:install_python
echo Downloading and installing the latest Python version... >> %LOGFILE%

REM Define the URL for the Python FTP page
set "FTP_PAGE=https://www.python.org/ftp/python/"
echo FTP_PAGE = %FTP_PAGE% >> %LOGFILE%

REM Create a temporary PowerShell script to handle the FTP scraping
set PS_SCRIPT=%TEMP%\get_latest_python.ps1

echo $ErrorActionPreference = "Stop" > %PS_SCRIPT%
echo try { >> %PS_SCRIPT%
echo     $htmlContent = Invoke-WebRequest -Uri "%FTP_PAGE%" >> %PS_SCRIPT%
echo     $versions = $htmlContent.Links ^| Where-Object { $_.href -match '^\d+\.\d+\.\d+/$' -and $_.href -notmatch '-rc' -and $_.href -notmatch 'b' } ^| ForEach-Object { $_.href -replace '/' } >> %PS_SCRIPT%
echo     $sortedVersions = $versions ^| Sort-Object { [System.Version]::Parse($_) } >> %PS_SCRIPT%
echo     $attempt = 0 >> %PS_SCRIPT%
echo     $latestStableVersion = $null >> %PS_SCRIPT%
echo     while ($attempt -lt 10 -and $latestStableVersion -eq $null) { >> %PS_SCRIPT%
echo         $versionIndex = -1 * ($attempt + 1) >> %PS_SCRIPT%
echo         $currentVersion = $sortedVersions[$versionIndex] >> %PS_SCRIPT%
echo         $latestStableUrl = "https://www.python.org/ftp/python/$currentVersion/python-$currentVersion-amd64.exe" >> %PS_SCRIPT%
echo         Write-Output "Attempting URL: $latestStableUrl" >> %PS_SCRIPT%
echo         try { >> %PS_SCRIPT%
echo             $response = Invoke-WebRequest -Uri $latestStableUrl -UseBasicParsing -Method Head >> %PS_SCRIPT%
echo             if ($response.StatusCode -eq 200) { >> %PS_SCRIPT%
echo                 $latestStableVersion = $currentVersion >> %PS_SCRIPT%
echo                 Write-Output "Selected URL: $latestStableUrl" >> %PS_SCRIPT%
echo             } else { >> %PS_SCRIPT%
echo                 Write-Output "Failed URL: $latestStableUrl" >> %PS_SCRIPT%
echo                 $attempt++ >> %PS_SCRIPT%
echo             } >> %PS_SCRIPT%
echo         } catch { >> %PS_SCRIPT%
echo             Write-Output "Exception on URL: $latestStableUrl - $_" >> %PS_SCRIPT%
echo             $attempt++ >> %PS_SCRIPT%
echo         } >> %PS_SCRIPT%
echo     } >> %PS_SCRIPT%
echo     if ($latestStableVersion -eq $null) { >> %PS_SCRIPT%
echo         throw "Failed to find a valid Python version after 10 attempts." >> %PS_SCRIPT%
echo     } >> %PS_SCRIPT%
echo     Write-Output "Selected URL: $latestStableUrl" >> %PS_SCRIPT%
echo     $latestStableUrl ^| Out-File %TEMP%\latest_stable_url.txt -Encoding ascii >> %PS_SCRIPT%
echo } catch { >> %PS_SCRIPT%
echo     Write-Error "Failed to retrieve Python versions: $_" >> %PS_SCRIPT%
echo     exit 1 >> %PS_SCRIPT%
echo } >> %PS_SCRIPT%

powershell -ExecutionPolicy Bypass -File %PS_SCRIPT% >> %LOGFILE% 2>>&1

if %ERRORLEVEL% neq 0 (
    echo PowerShell script failed. See log for details. >> %LOGFILE%
    goto end
)

if not exist %TEMP%\latest_stable_url.txt (
    echo Failed to retrieve the latest stable version from the FTP page. >> %LOGFILE%
    goto end
)

set /p LATEST_VERSION_URL=<%TEMP%\latest_stable_url.txt
set "LATEST_VERSION_URL=!LATEST_VERSION_URL!"

REM Create a temporary PowerShell script to handle the FTP scraping
set PS_SCRIPT=%TEMP%\get_latest_python.ps1

echo $ErrorActionPreference = "Stop" > %PS_SCRIPT%
echo try { >> %PS_SCRIPT%
echo     $htmlContent = Invoke-WebRequest -Uri "%FTP_PAGE%" >> %PS_SCRIPT%
echo     $versions = $htmlContent.Links ^| Where-Object { $_.href -match '^\d+\.\d+\.\d+/$' -and $_.href -notmatch '-rc' -and $_.href -notmatch 'b'} ^| ForEach-Object { $_.href -replace '/' } >> %PS_SCRIPT%
echo     $sortedVersions = $versions ^| Sort-Object { [System.Version]::Parse($_) } >> %PS_SCRIPT%
echo     $attempt = 0 >> %PS_SCRIPT%
echo     $latestStableVersion = $null >> %PS_SCRIPT%
echo     while ($attempt -lt 10 -and $latestStableVersion -eq $null) { >> %PS_SCRIPT%
echo         $versionIndex = -1 * ($attempt + 1) >> %PS_SCRIPT%
echo         $currentVersion = $sortedVersions[$versionIndex] >> %PS_SCRIPT%
echo         $latestStableUrl = "https://www.python.org/ftp/python/$currentVersion/python-$currentVersion-amd64.exe" >> %PS_SCRIPT%
echo         Write-Output "Attempting URL: $latestStableUrl" >> %PS_SCRIPT%
echo         try { >> %PS_SCRIPT%
echo             $response = Invoke-WebRequest -Uri $latestStableUrl -UseBasicParsing -Method Head >> %PS_SCRIPT%
echo             if ($response.StatusCode -eq 200) { >> %PS_SCRIPT%
echo                 $latestStableVersion = $currentVersion >> %PS_SCRIPT%
echo             } else { >> %PS_SCRIPT%
echo                 $attempt++ >> %PS_SCRIPT%
echo             } >> %PS_SCRIPT%
echo         } catch { >> %PS_SCRIPT%
echo             Write-Output "Failed URL: $latestStableUrl" >> %PS_SCRIPT%
echo             $attempt++ >> %PS_SCRIPT%
echo         } >> %PS_SCRIPT%
echo     } >> %PS_SCRIPT%
echo     if ($latestStableVersion -eq $null) { >> %PS_SCRIPT%
echo         throw "Failed to find a valid Python version after 10 attempts." >> %PS_SCRIPT%
echo     } >> %PS_SCRIPT%
echo     Write-Output "Selected URL: $latestStableUrl" >> %PS_SCRIPT%
echo     $latestStableUrl ^| Out-File %TEMP%\latest_stable_url.txt -Encoding ascii >> %PS_SCRIPT%
echo } catch { >> %PS_SCRIPT%
echo     Write-Error "Failed to retrieve Python versions: $_" >> %PS_SCRIPT%
echo     exit 1 >> %PS_SCRIPT%
echo } >> %PS_SCRIPT%

powershell -ExecutionPolicy Bypass -File %PS_SCRIPT% >> %LOGFILE% 2>>&1

if %ERRORLEVEL% neq 0 (
    echo PowerShell script failed. See log for details. >> %LOGFILE%
    goto end
)

if not exist %TEMP%\latest_stable_url.txt (
    echo Failed to retrieve the latest stable version from the FTP page. >> %LOGFILE%
    goto end
)

set /p LATEST_VERSION_URL=<%TEMP%\latest_stable_url.txt
if "%LATEST_VERSION_URL%"=="" (
    echo Failed to detect the latest Python version URL. >> %LOGFILE%
    echo Exiting...
    goto end
)
set "LATEST_VERSION_URL=!LATEST_VERSION_URL!"

echo LATEST_VERSION_URL before extraction: !LATEST_VERSION_URL! >> %LOGFILE%
set "LATEST_VERSION_URL=!LATEST_VERSION_URL!"

REM Check if LATEST_VERSION_URL is not empty
if "!LATEST_VERSION_URL!"=="" (
    echo Failed to detect the latest Python version URL. >> %LOGFILE%
    echo Exiting...
    goto end
)

echo Detected latest Python version URL: !LATEST_VERSION_URL! >> %LOGFILE%

REM Construct the full URL for the installer
set "fullUrl=!LATEST_VERSION_URL!"
echo Full URL: !fullUrl! >> %LOGFILE%
echo Full URL: !fullUrl!
set "pythonInstallerPath=%TEMP%\python-installer.exe"

REM Download the Python installer using PowerShell with a progress bar
powershell -Command "Invoke-WebRequest -Uri '!fullUrl!' -OutFile '!pythonInstallerPath!' -UseBasicParsing -Verbose" >> %LOGFILE% 2>>&1

REM Verify the download
if exist "!pythonInstallerPath!" (
    echo Python installer downloaded successfully. >> %LOGFILE%
    echo Proceeding with installation of Python... >> %LOGFILE%
) else (
    echo Failed to download Python installer. >> %LOGFILE%
    echo Exiting...
    goto end
)

REM Install Python unattended
start /wait "" "!pythonInstallerPath!" /passive InstallAllUsers=1 PrependPath=1 Include_pip=1

REM Install pip if not already installed
python -m ensurepip --upgrade >> %LOGFILE% 2>>&1
python -m pip install --upgrade pip >> %LOGFILE% 2>>&1

REM Detect Python installation path
for /f "delims=" %%A in ('powershell -command "(Get-Command python).Path"') do set "pythonPath=%%A"
set "pythonDir=%pythonPath:\python.exe=%"
set "scriptDir=%pythonDir%\Scripts"
echo Detected Python directory: %pythonDir% >> %LOGFILE%
echo Detected Scripts directory: %scriptDir% >> %LOGFILE%

REM Remove only invalid Python paths from PATH
for %%P in ("%PATH:;=" "%") do (
    if exist "%%~P\python.exe" (
        if "!newPath!" == "" (
            set "newPath=%%~P"
        ) else (
            set "newPath=!newPath!;%%~P"
        )
    )
)

REM Add the new Python paths
set "newPath=%pythonDir%;%scriptDir%;!newPath!"
echo New PATH: !newPath! >> %LOGFILE%

REM Update the system PATH
powershell -command "[System.Environment]::SetEnvironmentVariable('Path', '%newPath%', [System.EnvironmentVariableTarget]::Machine)" >> %LOGFILE% 2>>&1

REM Ensure pip is included in the PATH
set "scriptDir=%pythonDir%\Scripts"
if not exist "%scriptDir%\pip.exe" (
    echo Pip installation failed. >> %LOGFILE%
    echo Pip installation failed.
    goto end
)
set "newPath=!newPath!;%scriptDir%"

REM Verify the installation
echo Verifying Python installation... >> %LOGFILE%
python --version >> %LOGFILE% 2>>&1
set PYTHON_ERRORLEVEL=%errorlevel%
echo Verifying pip installation... >> %LOGFILE%
pip --version >> %LOGFILE% 2>>&1
set PIP_ERRORLEVEL=%errorlevel%

REM Clean up
del /f "!pythonInstallerPath!" >> %LOGFILE%
del /f "%PS_SCRIPT%" >> %LOGFILE%

REM Check if Python and pip were verified successfully
if "!PYTHON_ERRORLEVEL!"=="0" if "!PIP_ERRORLEVEL!"=="0" (
    REM Call function to check and run HCloud
    call :check_and_run_HCloud
)

:end
echo Script ended. >> %LOGFILE%
pause
exit
endlocal
