@echo off
rem Static PE audit of the production bridge (host-only, no loading).
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
dumpbin /exports phase10_hip_bridge\prod_build\amdhip64_7.dll > phase10_hip_bridge\prod_exports.txt || exit /b 1
dumpbin /imports phase10_hip_bridge\prod_build\amdhip64_7.dll > phase10_hip_bridge\prod_imports.txt || exit /b 1
dumpbin /headers phase10_hip_bridge\prod_build\amdhip64_7.dll > phase10_hip_bridge\prod_headers.txt || exit /b 1
echo AUDIT_OK
