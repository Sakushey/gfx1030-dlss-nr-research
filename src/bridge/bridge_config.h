// Phase 10 bridge backend-path configuration.
//
// The backend path is a COMPILE-TIME constant embedded in the binary:
//   production build (no DLSSNR_BRIDGE_TESTING): absolute HIP 6.4 DLL
//   test build (DLSSNR_BRIDGE_TESTING set):       absolute mock_hip6.dll
//
// There is intentionally NO runtime environment override: a production
// bridge must never be able to load an arbitrary DLL.
#pragma once

#ifdef DLSSNR_BRIDGE_TESTING
#define DLSSNR_BACKEND_PATH \
    L"C:\\Users\\danil\\Desktop\\gfx1030_soft_wmma_phase1\\phase10_hip_bridge\\mock_hip6.dll"
#else
#define DLSSNR_BACKEND_PATH \
    L"C:\\Program Files\\AMD\\ROCm\\6.4\\bin\\amdhip64_6.dll"
#endif
