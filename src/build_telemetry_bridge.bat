@echo off
rem Phase 16 telemetry bridge builds (host-only; MSVC 2022 Build Tools).
rem   prod_build\amdhip64_7.dll  - production bridge -> absolute HIP 6.4 DLL
rem   test_build\amdhip64_7.dll  - test bridge -> mock_hip6.dll (absolute)
rem Payload embedded: gfx1030_dlssnr_entryfixed.fatbin (entry-fixed module,
rem unchanged from phase14_entryfixed_bridge). Additions: registration
rem ledger + per-launch telemetry log + bounded VarParams/ConvParams1d
rem decode (convergence plan section 10). No other behavior change.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
set H64=<ROCM_ROOT>\6.4\include
set CFLAGS=/nologo /std:c++17 /EHsc /MT /O1 /D_CRT_SECURE_NO_WARNINGS /D__HIP_PLATFORM_AMD__ /I"%H64%"

if not exist prod_build mkdir prod_build
if not exist test_build mkdir test_build

echo [1/4] production telemetry bridge (entry-fixed payload)
cl %CFLAGS% /LD src\amdhip64_7.cpp src\registry_ident.cpp ^
   /link /DEF:src\exports.def /OUT:prod_build\amdhip64_7.dll || exit /b 1

echo [2/4] test telemetry bridge (mock backend, entry-fixed payload)
cl %CFLAGS% /DDLSSNR_BRIDGE_TESTING /LD src\amdhip64_7.cpp ^
   src\registry_ident.cpp /link /DEF:src\exports.def ^
   /OUT:test_build\amdhip64_7.dll || exit /b 1

echo [3/4] smoke test executable
cl %CFLAGS% src\hip_bridge_smoke.cpp /link /OUT:hip_bridge_smoke.exe || exit /b 1

echo [4/4] registration smoke test executable
cl %CFLAGS% src\hip_bridge_reg_smoke.cpp /link /OUT:hip_bridge_reg_smoke.exe || exit /b 1

echo TELEMETRY_BRIDGE_BUILD_OK
