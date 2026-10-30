@echo off
setlocal
cd /d "%~dp0"

if not exist "lib\mysql-connector-j-26.10.0.jar" (
    echo MySQL JDBC driver nahi mila: lib\mysql-connector-j-26.10.0.jar
    echo README-no-maven.md mein diye gaye step 1 ko dekhein.
    pause
    exit /b 1
)

if not exist "database.properties" (
    copy "database.properties.example" "database.properties" >nul
    echo database.properties ban gayi. Is file mein apna MySQL password bhariye, phir yeh .bat dobara chalaiye.
    notepad "database.properties"
    pause
    exit /b 1
)

if not exist "build-no-maven" mkdir "build-no-maven"
echo Java backend taiyar ho raha hai...
javac -encoding UTF-8 -cp "lib\mysql-connector-j-26.10.0.jar" -d "build-no-maven" "backend-no-maven\ZovyaServer.java"
if errorlevel 1 (
    echo Java compile nahi hua. Java JDK install hai aur javac PATH mein hai, yeh check karein.
    pause
    exit /b 1
)

echo Backend start ho raha hai. Is window ko band na karein.
java -cp "build-no-maven;lib\mysql-connector-j-26.10.0.jar" ZovyaServer
pause
