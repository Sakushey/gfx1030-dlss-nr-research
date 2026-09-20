@echo off
rem Host-only compile of the HIP ABI structure fingerprint programs.
rem Builds against HIP 6.4 and HIP 7.1 headers independently.
call "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat" >nul
set H64=C:\Program Files\AMD\ROCm\6.4\include
set H71=C:\Program Files\AMD\ROCm\7.1\include
cl /nologo /std:c++17 /EHsc /D_CRT_SECURE_NO_WARNINGS /D__HIP_PLATFORM_AMD__ /I"%H64%" /Fe:phase10_hip_bridge\abi_6_4_fingerprint.exe phase10_hip_bridge\abi_6_4_fingerprint.cpp || exit /b 1
cl /nologo /std:c++17 /EHsc /D_CRT_SECURE_NO_WARNINGS /D__HIP_PLATFORM_AMD__ /I"%H71%" /Fe:phase10_hip_bridge\abi_7_1_fingerprint.exe phase10_hip_bridge\abi_7_1_fingerprint.cpp || exit /b 1
echo FINGERPRINTS_BUILT_OK
