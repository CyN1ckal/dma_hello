// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

// CRT-free payload. Imports only MessageBoxA so the mapper can
// resolve it from notepad's already-loaded user32.
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" __declspec(dllexport) void LaunchHello(void)
{
    MessageBoxA(
        NULL,
        "Hello from DMA!\nInjected without LoadLibrary.",
        "DMA Injection PoC",
        MB_OK | MB_ICONINFORMATION
    );
}
