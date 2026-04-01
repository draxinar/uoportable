# UO Portable

Makes classic Ultima Online clients portable by intercepting registry
queries and returning paths derived from the client's own location on
disk.

## Problem

All classic UO clients read their installation path from the Windows
registry:

```
HKLM\SOFTWARE\Origin Worlds Online\Ultima Online\1.0
    ExePath    = C:\Program Files\Ultima Online\client.exe
    InstCDPath = D:\
```

Without these keys the client shows "Ultima Online does not appear to be
installed correctly" and refuses to start. This makes it impossible to
relocate, duplicate, or run multiple client installations without editing
the registry each time.

## Solution

Place `dsound.dll` in the same directory as `client.exe`. The proxy
intercepts UO registry queries and returns paths based on the client
executable's actual location (via `GetModuleFileNameA`). Each client
directory becomes fully self-contained - no registry keys needed.

Since `advapi32.dll` is a Windows Known DLL (always loaded from
System32), it cannot be proxied directly. Instead, `dsound.dll` (which
is not a Known DLL and is imported by every classic UO client) acts as
the entry point: the loader picks up the local copy, which patches the
client's import table at runtime to intercept the advapi32 registry
functions. All DirectSound calls are forwarded to the real system DLL.

## Usage on Windows

Place `dsound.dll` in the same directory as `client.exe`.

## Usage with Wine

Place `dsound.dll` next to `client.exe` and tell Wine to load the
native version:

```
WINEDLLOVERRIDES="dsound=n" wine client.exe
```

Or set the override permanently for a prefix:

```
wine reg add 'HKCU\Software\Wine\DllOverrides' /v dsound /d native /f
```

## Building

Requires MinGW cross-compiler:

```
make
```

Produces `dsound.dll`.

## Registry key alternative

If you prefer the traditional approach, you can download and import the
[`uo.reg`](uo.reg) registry key. Edit the paths inside to match your
installation directory, then double-click the file or run:

```
regedit uo.reg
```
