@echo off
rem Phase 10 bridge builds (host-only; MSVC 2022 Build Tools).
rem   prod_build\amdhip64_7.dll - production bridge -> absolute HIP 6.4 DLL
rem   test_build\amdhip64_7.dll - test bridge -> mock_hip6.dll (absolute)
rem   mock_hip6.dll            - deterministic mock backend
rem   hip_bridge_smoke.exe     - host test executable (no GPU)
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set H64=C:\Program Files\AMD\ROCm\6.4\include
set CFLAGS=/nologo /std:c++17 /EHsc /MT /O1 /D_CRT_SECURE_NO_WARNINGS /D__HIP_PLATFORM_AMD__ /I"%H64%"

if not exist phase10_hip_bridge\prod_build mkdir phase10_hip_bridge\prod_build
if not exist phase10_hip_bridge\test_build mkdir phase10_hip_bridge\test_build

echo [1/4] production bridge
cl %CFLAGS% /LD phase10_hip_bridge\amdhip64_7.cpp phase10_hip_bridge\registry_ident.cpp ^
   /link /DEF:phase10_hip_bridge\exports.def ^
   /OUT:phase10_hip_bridge\prod_build\amdhip64_7.dll || exit /b 1

echo [2/4] test bridge (mock backend)
cl %CFLAGS% /DDLSSNR_BRIDGE_TESTING /LD phase10_hip_bridge\amdhip64_7.cpp ^
   phase10_hip_bridge\registry_ident.cpp /link /DEF:phase10_hip_bridge\exports.def ^
   /OUT:phase10_hip_bridge\test_build\amdhip64_7.dll || exit /b 1

echo [3/4] mock backend
cl %CFLAGS% /LD phase10_hip_bridge\mock_hip6.cpp /link /DEF:phase10_hip_bridge\exports.def ^
   /OUT:phase10_hip_bridge\mock_hip6.dll || exit /b 1

echo [4/5] smoke test executable
cl %CFLAGS% phase10_hip_bridge\hip_bridge_smoke.cpp ^
   /link /OUT:phase10_hip_bridge\hip_bridge_smoke.exe || exit /b 1

echo [5/5] registration smoke test executable
cl %CFLAGS% phase10_hip_bridge\hip_bridge_reg_smoke.cpp ^
   /link /OUT:phase10_hip_bridge\hip_bridge_reg_smoke.exe || exit /b 1

echo BRIDGE_BUILD_OK
