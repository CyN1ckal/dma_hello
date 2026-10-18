// Copyright (c) 2026 CyNickal Software LLC
// SPDX-License-Identifier: MIT

// CRT-free payload. MessageBeep returns immediately. MessageBoxA on the
// PeekMessageW thread stalls Ark inside its modal loop.
#include <windows.h>

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID)
{
    return TRUE;
}

extern "C" __declspec(dllexport) void LaunchHello(void)
{
    MessageBeep(MB_ICONINFORMATION);
}