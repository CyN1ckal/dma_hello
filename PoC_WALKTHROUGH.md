<!-- Copyright (c) 2026 CyNickal Software LLC. SPDX-License-Identifier: MIT -->

# DMA injector walkthrough

Developed and verified on a live Windows 11 25H2 (x64) machine. Visual Studio 2022 or 2026, MemProcFS over an FPGA.

## Build

```powershell
.\build.bat
```

`build.bat` is a VS x64 developer shell plus the CMake `Debug` preset. From that same shell, the other path is:

```powershell
cmake --preset Release
cmake --build --preset Release
```

CMake writes `dma_hello.exe`, `dma_hello_tests.exe`, and the MemProcFS runtime, including `dbghelp.dll` and `symsrv.dll`, into `bin\`. It also copies `hello_dll.dll` and `beep_dll.dll` to `hello_dll\` and to `bin\`. The commands below are run from the repository root, where `hello_dll\` is the path `--hello` and `--beep` open. The loader uses the `vmm.dll` in `bin\`, next to the executable.

## Tests without hardware

```powershell
.\bin\dma_hello_tests.exe "~[system]"
```

`[system]` cases do not open a device. Real filters are `~[system]`, `[integration]`, and `[stress]`. `[stress]` is the long run. A tag that is not on a `TEST_CASE` matches nothing and exits 2. The suite runs on `SimulatedMemory`. A passing run does not execute `ntoskrnl` and does not show that a live boot accepted the writes.

JUnit output, as in `.github/workflows/tests.yml`:

```powershell
.\bin\dma_hello_tests.exe "~[system]" -r junit::out=test-results.xml -r console
```

`tests/cpp/metrics.hpp` can write `pfn-metrics.csv` and `timeline.log` into a directory a test chooses. A normal injector run does not emit those files.

## Payloads

`--hello` is the default. It maps `hello_dll\hello_dll.dll` and shows "Hello from DMA!". `--beep` maps `hello_dll\beep_dll.dll` and calls `MessageBeep`. The last of `--hello`, `--beep`, and `--dll` wins. Both DLLs export `LaunchHello`.

`MessageBoxA` runs on the `PeekMessageW` thread. Use `--beep` for a process that cannot sit inside that modal loop. `kernel32!GetTickCount` and `GetTickCount64` are refused.

Notepad:

```powershell
.\bin\dma_hello.exe --hello --device fpga://
```

Ark:

```powershell
.\bin\dma_hello.exe --ark --beep --device fpga://
```

Click the target window so `PeekMessageW` runs. The stub fires once, calls `LaunchHello`, and returns to the real function. A jump that was already on `PeekMessageW` stays in the chain. A second run that still points at this injector's stub is refused.

`deploy_to_target.bat \\server\poc` runs on the build PC. It builds the Release preset and copies both DLLs to `hello_dll\` under that directory. `DMA_DEPLOY_DIR` is the same destination when you omit the argument. The copy puts `vmm.dll`, `dbghelp.dll`, and `symsrv.dll` in the parent of `bin` and removes any copy of those DLLs inside `bin`. Start the process with that parent as the current directory. An extra `vmm.dll` in `bin` loads first and hides symbol DLLs placed beside the working directory.

## When a run stops

| Symptom | What it means |
| :--- | :--- |
| `failed to open MemProcFS device fpga://` | The FPGA device string did not open. Check the USB link. The loader opens `vmm.dll` from the executable directory before the working directory. |
| `DLL not found` | The process was started from a directory that does not contain `hello_dll\hello_dll.dll` or `hello_dll\beep_dll.dll`. |
| `already hooked; refusing a second COW` | `PeekMessageW` already jumps to this injector's stub. Restart the target before another inject. |
| `is a shared image` | `kernel32.dll` or `kernelbase.dll` `GetTickCount` or `GetTickCount64` was named. The log text is `is a shared image; patching it hangs the machine`. The default hook is `user32!PeekMessageW`. |
