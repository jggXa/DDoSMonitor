@echo off
rem ============================================================================
rem  DDoSMonitor 构建脚本（JDK 21）
rem  1) 定位 javac / jar（JAVA_HOME → PATH → 常见安装位置）
rem  2) 缺少 lib\jna.jar 时用 curl 从 Maven Central 下载（Npcap 抓包后端需要）
rem  3) 用 --release 21 编译：核心零依赖；NpcapJnaSource 仅在 jna.jar 存在时编译
rem  4) 打包可运行 jar：dist\DDoSMonitor.jar（含 JNA 及其各平台本机库）
rem ============================================================================
setlocal enabledelayedexpansion
rem 记录调用者的原代码页，脚本结束时恢复：chcp 65001 是全局设置，
rem 不恢复会让调用者的 cmd 会话一直停留在 UTF-8 代码页。
for /f "tokens=2 delims=:" %%A in ('chcp') do set "OLDCP=%%A"
set "OLDCP=%OLDCP: =%"
chcp 65001 >nul
cd /d "%~dp0"
set "ROOT=%~dp0"

set "LIB=lib"
set "OUT=out"
set "BUILD=build"
set "STAGE=%BUILD%\jar"
set "DIST=dist"
set "JAR_NAME=DDoSMonitor.jar"
set "JNA_VER=5.14.0"
set "JNA_JAR=%LIB%\jna.jar"
set "JNA_URL=https://repo1.maven.org/maven2/net/java/dev/jna/jna/%JNA_VER%/jna-%JNA_VER%.jar"

echo ============================================================
echo  DDoSMonitor 构建（Java 21 源级，JDK 21+ 编译）
echo ============================================================

rem ---------------------------------------------------------- 1. 找 JDK
set "JAVAC="
if defined JAVA_HOME if exist "%JAVA_HOME%\bin\javac.exe" set "JAVAC=%JAVA_HOME%\bin\javac.exe"
if not defined JAVAC for %%I in (javac.exe) do if not "%%~$PATH:I"=="" set "JAVAC=%%~$PATH:I"
if not defined JAVAC (
  for %%D in ("D:\jdk-21*" "D:\java21" "C:\Program Files\Eclipse Adoptium\jdk-21*"
              "C:\Program Files\Java\jdk-21*" "C:\Program Files\Microsoft\jdk-21*"
              "%USERPROFILE%\.jdks\*") do (
    if not defined JAVAC if exist "%%~fD\bin\javac.exe" set "JAVAC=%%~fD\bin\javac.exe"
  )
)
if not defined JAVAC (
  echo [错误] 找不到 javac.exe。请安装 JDK 21 或更高版本，并设置 JAVA_HOME。
  goto :fail
)
for %%I in ("%JAVAC%") do set "JAR=%%~dpIjar.exe"
if not exist "%JAR%" (
  echo [错误] 在同目录找不到 jar.exe: %JAR%
  goto :fail
)
echo [1/4] javac: %JAVAC%
"%JAVAC%" -version
if errorlevel 1 (
  echo [错误] javac 无法执行。
  goto :fail
)

rem ---------------------------------------------------------- 2. jna.jar
if not exist "%LIB%" mkdir "%LIB%"
if exist "%JNA_JAR%" (
  echo [2/4] 已存在 %JNA_JAR%，跳过下载。
) else (
  echo [2/4] 下载 JNA（仅 Npcap 抓包后端需要）...
  curl.exe -fsSL --connect-timeout 15 -o "%JNA_JAR%" "%JNA_URL%"
  if exist "%JNA_JAR%" (
    echo       下载完成: %JNA_JAR%
  ) else (
    echo       [警告] 下载失败。将只编译核心：Npcap 后端不可用，
    echo              可用 --source=sim 或 --source=external（dumpcap/tcpdump）替代。
  )
)

rem ---------------------------------------------------------- 3. 编译
if not exist "%OUT%" mkdir "%OUT%"
set "SRC="
for %%F in (*.java) do if /i not "%%F"=="NpcapJnaSource.java" if /i not "%%F"=="WindowsAnsi.java" set "SRC=!SRC! "%%F""
echo [3/4] 编译核心（--release 21）...
"%JAVAC%" -encoding UTF-8 --release 21 -Xlint:all -d "%OUT%" !SRC!
if errorlevel 1 goto :fail

if exist "%JNA_JAR%" (
  echo       编译 Npcap 抓包后端（-cp "%OUT%;%JNA_JAR%"）...
  "%JAVAC%" -encoding UTF-8 --release 21 -cp "%OUT%;%JNA_JAR%" -d "%OUT%" "NpcapJnaSource.java" "WindowsAnsi.java"
  if errorlevel 1 goto :fail
  if not exist "%OUT%\NpcapJnaSource.class" goto :fail
) else (
  echo       跳过 Npcap 后端（缺少 %JNA_JAR%）
)

rem ---------------------------------------------------------- 4. 打包 jar
if exist "%BUILD%" rmdir /s /q "%BUILD%"
mkdir "%STAGE%"
if not exist "%DIST%" mkdir "%DIST%"

if exist "%JNA_JAR%" (
  echo [4/4] 打包 dist\%JAR_NAME%（合并 JNA 及其本机库）...
  pushd "%STAGE%"
  "%JAR%" xf "%ROOT%%JNA_JAR%"
  popd
  rem JNA 自带的 MANIFEST 里写着 Main-Class: com.sun.jna.Native，必须删掉换成我们自己的
  del /q "%STAGE%\META-INF\MANIFEST.MF" 2>nul
  del /q "%STAGE%\META-INF\*.SF" 2>nul
  del /q "%STAGE%\META-INF\*.RSA" 2>nul
  del /q "%STAGE%\META-INF\*.DSA" 2>nul
  set "FATJAR=1"
) else (
  echo [4/4] 打包 dist\%JAR_NAME%（无 JNA，Npcap 后端不可用）...
  set "FATJAR=0"
)
copy /y "%OUT%\*.class" "%STAGE%\" >nul
if errorlevel 1 goto :fail

> "%BUILD%\MANIFEST.MF" echo Manifest-Version: 1.0
>> "%BUILD%\MANIFEST.MF" echo Main-Class: DDoSMonitor
>> "%BUILD%\MANIFEST.MF" echo Implementation-Title: DDoSMonitor
>> "%BUILD%\MANIFEST.MF" echo Implementation-Version: 1.0
>> "%BUILD%\MANIFEST.MF" echo Implementation-Vendor: DDoSMonitor

"%JAR%" --create --file "%DIST%\%JAR_NAME%" --manifest "%BUILD%\MANIFEST.MF" -C "%STAGE%" .
if errorlevel 1 goto :fail
if not exist "%DIST%\%JAR_NAME%" goto :fail
for %%F in ("%DIST%\%JAR_NAME%") do echo       jar 大小: %%~zF 字节

echo.
echo ============================================================
echo  编译 + 打包成功。
echo ------------------------------------------------------------
echo  可运行 jar（推荐，无需 -cp）:
if "%FATJAR%"=="1" (
  echo    java -Dstdout.encoding=UTF-8 -jar dist\%JAR_NAME% --source=sim --yes
  echo    java -Dstdout.encoding=UTF-8 -jar dist\%JAR_NAME% --list-ifaces
  echo    java -Dstdout.encoding=UTF-8 -jar dist\%JAR_NAME% --yes     ^(真实抓包，需要管理员^)
) else (
  echo    java -Dstdout.encoding=UTF-8 -jar dist\%JAR_NAME% --source=sim --yes
  echo    ^(缺少 lib\jna.jar，Npcap 后端未打入；--source=external / sim 仍可用^)
)
echo.
echo  自检（145 项纯逻辑检查）:
echo    java -cp dist\%JAR_NAME% SelfTest
echo.
echo  也可继续用 class 目录方式运行:
echo    java -Dstdout.encoding=UTF-8 -cp "out;lib\jna.jar" DDoSMonitor --yes
echo ============================================================
if defined OLDCP chcp %OLDCP% >nul
exit /b 0

:fail
echo.
echo [错误] 构建失败，请把上面的错误信息反馈给我。
if defined OLDCP chcp %OLDCP% >nul
exit /b 1
