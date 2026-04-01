/*
 * dsound.dll proxy - makes classic UO clients portable on Windows
 *
 * Place as dsound.dll next to client.exe. All DirectSound calls are
 * forwarded to the real system DLL while the client's import table is
 * patched to intercept advapi32 registry queries.
 *
 * dsound.dll is not a Windows Known DLL, so the loader picks up the
 * local copy from the application directory.
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <string.h>

/*
 * dsound.dll forwarding
 */

#define DSOUND_FUNCS \
	F(DirectSoundCreate) \
	F(DirectSoundCreate8) \
	F(DirectSoundCaptureCreate) \
	F(DirectSoundCaptureCreate8) \
	F(DirectSoundEnumerateA) \
	F(DirectSoundEnumerateW) \
	F(DirectSoundCaptureEnumerateA) \
	F(DirectSoundCaptureEnumerateW) \
	F(DirectSoundFullDuplexCreate) \
	F(GetDeviceID)

#define F(name) FARPROC p_##name;
DSOUND_FUNCS
#undef F

#define F(name) \
	__attribute__((naked)) void name(void) { \
		__asm__("jmp *_p_" #name); \
	}
DSOUND_FUNCS
#undef F

static HMODULE real_dsound;

static void load_real_dsound(void)
{
	char sysdir[MAX_PATH];

	GetSystemDirectoryA(sysdir, MAX_PATH);
	strcat(sysdir, "\\dsound.dll");
	real_dsound = LoadLibraryA(sysdir);
	if (!real_dsound)
		return;

#define F(name) p_##name = GetProcAddress(real_dsound, #name);
	DSOUND_FUNCS
#undef F
}

/*
 * Registry hook
 */

#define FAKE_UO_KEY  ((HKEY)(ULONG_PTR)0xDEAD0001)
#define UO_PREFIX    "SOFTWARE\\Origin Worlds Online\\Ultima Online"
#define UO_PREFIX_LEN (sizeof(UO_PREFIX) - 1)

static char exe_path[MAX_PATH];
static char exe_dir[MAX_PATH];

static LONG (WINAPI *orig_RegOpenKeyExA)(HKEY, LPCSTR, DWORD, REGSAM, PHKEY);
static LONG (WINAPI *orig_RegQueryValueExA)(HKEY, LPCSTR, LPDWORD, LPDWORD,
                                            LPBYTE, LPDWORD);
static LONG (WINAPI *orig_RegCreateKeyExA)(HKEY, LPCSTR, DWORD, LPSTR, DWORD,
                                           REGSAM, LPSECURITY_ATTRIBUTES,
                                           PHKEY, LPDWORD);
static LONG (WINAPI *orig_RegSetValueExA)(HKEY, LPCSTR, DWORD, DWORD,
                                          const BYTE *, DWORD);
static LONG (WINAPI *orig_RegCloseKey)(HKEY);

static int is_uo_subkey(HKEY hKey, LPCSTR lpSubKey)
{
	if (hKey != HKEY_LOCAL_MACHINE || !lpSubKey)
		return 0;
	return _strnicmp(lpSubKey, UO_PREFIX, UO_PREFIX_LEN) == 0;
}

static LONG return_string(const char *val, LPDWORD lpType,
                          LPBYTE lpData, LPDWORD lpcbData)
{
	DWORD len = (DWORD)strlen(val) + 1;

	if (lpType)
		*lpType = REG_SZ;
	if (!lpData) {
		*lpcbData = len;
		return ERROR_SUCCESS;
	}
	if (*lpcbData < len) {
		*lpcbData = len;
		return ERROR_MORE_DATA;
	}
	memcpy(lpData, val, len);
	*lpcbData = len;
	return ERROR_SUCCESS;
}

static LONG WINAPI hook_RegOpenKeyExA(HKEY hKey, LPCSTR lpSubKey,
                                      DWORD ulOptions, REGSAM samDesired,
                                      PHKEY phkResult)
{
	if (is_uo_subkey(hKey, lpSubKey)) {
		*phkResult = FAKE_UO_KEY;
		return ERROR_SUCCESS;
	}
	return orig_RegOpenKeyExA(hKey, lpSubKey, ulOptions, samDesired,
	                          phkResult);
}

static LONG WINAPI hook_RegQueryValueExA(HKEY hKey, LPCSTR lpValueName,
                                         LPDWORD lpReserved, LPDWORD lpType,
                                         LPBYTE lpData, LPDWORD lpcbData)
{
	if (hKey == FAKE_UO_KEY && lpValueName) {
		if (_stricmp(lpValueName, "ExePath") == 0 ||
		    _stricmp(lpValueName, "StartExePath") == 0)
			return return_string(exe_path, lpType, lpData, lpcbData);
		if (_stricmp(lpValueName, "InstCDPath") == 0)
			return return_string(exe_dir, lpType, lpData, lpcbData);
		return ERROR_FILE_NOT_FOUND;
	}
	return orig_RegQueryValueExA(hKey, lpValueName, lpReserved, lpType,
	                             lpData, lpcbData);
}

static LONG WINAPI hook_RegCreateKeyExA(HKEY hKey, LPCSTR lpSubKey,
                                        DWORD Reserved, LPSTR lpClass,
                                        DWORD dwOptions, REGSAM samDesired,
                                        LPSECURITY_ATTRIBUTES lpSA,
                                        PHKEY phkResult,
                                        LPDWORD lpdwDisposition)
{
	if (is_uo_subkey(hKey, lpSubKey)) {
		*phkResult = FAKE_UO_KEY;
		if (lpdwDisposition)
			*lpdwDisposition = REG_OPENED_EXISTING_KEY;
		return ERROR_SUCCESS;
	}
	return orig_RegCreateKeyExA(hKey, lpSubKey, Reserved, lpClass,
	                            dwOptions, samDesired, lpSA, phkResult,
	                            lpdwDisposition);
}

static LONG WINAPI hook_RegSetValueExA(HKEY hKey, LPCSTR lpValueName,
                                       DWORD Reserved, DWORD dwType,
                                       const BYTE *lpData, DWORD cbData)
{
	if (hKey == FAKE_UO_KEY)
		return ERROR_SUCCESS;
	return orig_RegSetValueExA(hKey, lpValueName, Reserved, dwType,
	                           lpData, cbData);
}

static LONG WINAPI hook_RegCloseKey(HKEY hKey)
{
	if (hKey == FAKE_UO_KEY)
		return ERROR_SUCCESS;
	return orig_RegCloseKey(hKey);
}

/*
 * IAT patching
 */

static void patch_iat_entry(HMODULE base, const char *dll_name,
                            const char *func_name, ULONG_PTR hook,
                            ULONG_PTR *orig)
{
	IMAGE_DOS_HEADER *dos;
	IMAGE_NT_HEADERS *nt;
	IMAGE_IMPORT_DESCRIPTOR *imp;
	DWORD rva;

	dos = (IMAGE_DOS_HEADER *)base;
	nt = (IMAGE_NT_HEADERS *)((BYTE *)base + dos->e_lfanew);
	rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT]
	          .VirtualAddress;
	if (!rva)
		return;

	imp = (IMAGE_IMPORT_DESCRIPTOR *)((BYTE *)base + rva);
	for (; imp->Name; imp++) {
		IMAGE_THUNK_DATA *orig_thunk, *thunk;

		if (_stricmp((const char *)((BYTE *)base + imp->Name),
		             dll_name) != 0)
			continue;

		orig_thunk = (IMAGE_THUNK_DATA *)
		    ((BYTE *)base + imp->OriginalFirstThunk);
		thunk = (IMAGE_THUNK_DATA *)
		    ((BYTE *)base + imp->FirstThunk);

		for (; orig_thunk->u1.AddressOfData; orig_thunk++, thunk++) {
			IMAGE_IMPORT_BY_NAME *name;
			DWORD old_protect;

			if (orig_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				continue;

			name = (IMAGE_IMPORT_BY_NAME *)
			    ((BYTE *)base + orig_thunk->u1.AddressOfData);
			if (strcmp(name->Name, func_name) != 0)
				continue;

			*orig = thunk->u1.Function;
			VirtualProtect(&thunk->u1.Function, sizeof(ULONG_PTR),
			               PAGE_READWRITE, &old_protect);
			thunk->u1.Function = hook;
			VirtualProtect(&thunk->u1.Function, sizeof(ULONG_PTR),
			               old_protect, &old_protect);
			return;
		}
	}
}

static void install_hooks(void)
{
	HMODULE base = GetModuleHandleA(NULL);

	patch_iat_entry(base, "advapi32.dll", "RegOpenKeyExA",
	                (ULONG_PTR)hook_RegOpenKeyExA,
	                (ULONG_PTR *)&orig_RegOpenKeyExA);
	patch_iat_entry(base, "advapi32.dll", "RegQueryValueExA",
	                (ULONG_PTR)hook_RegQueryValueExA,
	                (ULONG_PTR *)&orig_RegQueryValueExA);
	patch_iat_entry(base, "advapi32.dll", "RegCreateKeyExA",
	                (ULONG_PTR)hook_RegCreateKeyExA,
	                (ULONG_PTR *)&orig_RegCreateKeyExA);
	patch_iat_entry(base, "advapi32.dll", "RegSetValueExA",
	                (ULONG_PTR)hook_RegSetValueExA,
	                (ULONG_PTR *)&orig_RegSetValueExA);
	patch_iat_entry(base, "advapi32.dll", "RegCloseKey",
	                (ULONG_PTR)hook_RegCloseKey,
	                (ULONG_PTR *)&orig_RegCloseKey);
}

/*
 * Entry point
 */

BOOL WINAPI DllMain(HINSTANCE hDll, DWORD reason, LPVOID reserved)
{
	char *sep;

	(void)reserved;

	if (reason != DLL_PROCESS_ATTACH)
		return TRUE;

	DisableThreadLibraryCalls(hDll);

	GetModuleFileNameA(NULL, exe_path, MAX_PATH);
	strcpy(exe_dir, exe_path);
	sep = strrchr(exe_dir, '\\');
	if (sep)
		sep[1] = '\0';
	else
		strcpy(exe_dir, ".\\");

	load_real_dsound();
	install_hooks();

	return TRUE;
}
