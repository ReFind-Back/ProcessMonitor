// Copyright (c) 2026 ReFind-Back
// This code is licensed under the MIT License, see LICENSE file for details

// ProcessMonitor.c
// Lightweight system tray tool to monitor and terminate abnormal processes.
// Version 0.48
// For users: read the manual (monitor_manual.txt) for usage instructions.
// For developers: code is kept simple and well-commented.

// Force Windows subsystem to hide console window (for MSVC)
#ifdef _MSC_VER
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")
#endif

#define _WIN32_WINNT 0x0600
#ifndef PBT_APMRESUMEHIBERNATE
#define PBT_APMRESUMEHIBERNATE 0x000A
#endif
#define _CRT_SECURE_NO_WARNINGS
#define INITGUID

#include <windows.h>
#include <shellapi.h>
#include <commctrl.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <wchar.h>
#include <sys/stat.h>
#include <errno.h>
#include <versionhelpers.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "comctl32.lib")

// -------------------- Configuration Constants --------------------
#define VERSION_STRING L"0.48"
#define DEFAULT_MONITOR_INTERVAL_MS 5000
#define DEFAULT_CPU_THRESHOLD_PERCENT 80
#define DEFAULT_MEM_THRESHOLD_MB 500
#define DEFAULT_HANG_TIMEOUT_MS 5000
#define DEFAULT_LOG_MAX_SIZE_BYTES (1 * 1024 * 1024) // 1 MB
#define DEFAULT_MAX_HUNG_WINDOWS 500
#define DEFAULT_NOTIFY_ON_TERMINATION 0
#define MAX_EXCLUDE_COUNT 32
#define MAX_PATH_LEN 260
#define MAX_LONG_PATH 32768

#define MIN_MONITOR_INTERVAL_MS 1000
#define MAX_MONITOR_INTERVAL_MS 60000
#define MIN_CPU_THRESHOLD 1
#define MAX_CPU_THRESHOLD 100
#define MIN_MEM_THRESHOLD_MB 1
#define MAX_MEM_THRESHOLD_MB 65536
#define MIN_HANG_TIMEOUT_MS 1000
#define MAX_HANG_TIMEOUT_MS 30000
#define MIN_LOG_SIZE_BYTES 1024
#define MAX_LOG_SIZE_BYTES 100 * 1024 * 1024
#define MIN_MAX_HUNG_WINDOWS 10
#define MAX_MAX_HUNG_WINDOWS 5000

#define TERMINATE_RETRY_LIMIT 5
#define LOG_RENAME_RETRY_LIMIT 10
#define INTERNAL_PATH_BUFFER_SIZE MAX_LONG_PATH
#define MAX_BACKOFF_WAIT_MS 60000
#define CONFIG_POLL_INTERVAL_MS 5000
#define CRITICAL_SECTION_SPIN_COUNT 4000

// Balloon frequency control
#define SUSPICIOUS_BALLOON_COOLDOWN_MS (5 * 60 * 1000)         // 5 minutes per process
#define CONFIG_FAIL_BALLOON_COOLDOWN_MS (10 * 60 * 1000)       // 10 minutes
#define ENCODING_WARNING_COOLDOWN_MS (7 * 24 * 60 * 60 * 1000) // 1 week
#define BALLOON_CLEANUP_INTERVAL_MS (60 * 60 * 1000)           // 1 hour
#define WARNING_COOLDOWN_MS (7 * 24 * 60 * 60 * 1000)          // 1 week for general warnings
#define LOG_FAIL_BALLOON_COOLDOWN_MS (60 * 60 * 1000)          // 1 hour for log failure warnings

#define CONFIG_FILE L"config.ini"
#define LOG_FILE L"monitor.log"
#define LOG_FILE_OLD L"monitor.log.old"
#define LOG_TEMP_FILE L"monitor.log.tmp"
#define MANUAL_FILE L"monitor_manual.txt"
#define README_FILE L"README.txt"
#define WM_TRAYICON (WM_USER + 100)

// Menu IDs
#define IDM_START 1001
#define IDM_STOP 1002
#define IDM_VIEWLOG 1003
#define IDM_VIEWCONFIG 1004
#define IDM_EXIT 1005
#define IDM_VIEWMANUAL 1006

// Exponential backoff delays for log rotation (ms)
static const DWORD LOG_RENAME_DELAYS[] = {100, 200, 400, 800, 1600, 3200, 5000, 5000, 5000, 5000};

// -------------------- Forward declarations --------------------
typedef struct _BALLOON_COOLDOWN BALLOON_COOLDOWN;
typedef struct _PROCESS_HISTORY PROCESS_HISTORY;
typedef struct _HUNG_PROCESS_NODE HUNG_PROCESS_NODE;
typedef struct _ENUM_HUNG_PARAMS ENUM_HUNG_PARAMS;
typedef struct _CONFIG CONFIG;
typedef struct _GLOBAL GLOBAL;

// Balloon cooldown linked list
struct _BALLOON_COOLDOWN
{
    WCHAR processName[MAX_PATH_LEN];
    ULONGLONG lastTick;
    struct _BALLOON_COOLDOWN *next;
};

// Configuration structure
struct _CONFIG
{
    DWORD monitorIntervalMs;
    DWORD cpuThresholdPercent;
    DWORD memThresholdMb;
    DWORD hangTimeoutMs;
    DWORD logMaxSizeBytes;
    DWORD maxHungWindows;
    BOOL notifyOnTermination;
    WCHAR excludeList[MAX_EXCLUDE_COUNT][MAX_PATH_LEN];
    int excludeCount;
    BOOL monitoringDefault;
};

// Process history linked list
struct _PROCESS_HISTORY
{
    DWORD pid;
    FILETIME ftCreate;
    FILETIME ftKernel;
    FILETIME ftUser;
    LARGE_INTEGER perfTime;
    int terminateAttempts;
    int terminateAttemptsHung;
    int terminateLogSent;
    int terminateLogSentHung;
    BOOL seen;
    struct _PROCESS_HISTORY *next;
};

// Hung process list node
struct _HUNG_PROCESS_NODE
{
    DWORD pid;
    struct _HUNG_PROCESS_NODE *next;
};

// EnumWindows parameters
struct _ENUM_HUNG_PARAMS
{
    HUNG_PROCESS_NODE **head;
    DWORD hangTimeoutMs;
    DWORD maxWindows;
    DWORD scannedCount;
    HANDLE stopEvent;
};

// Global state
struct _GLOBAL
{
    HINSTANCE hInst;
    HWND hWnd;
    HANDLE hMonitorThread;
    HANDLE hStopEvent;
    volatile LONG programRunning;
    volatile LONG monitorActive;
    CRITICAL_SECTION csLog;
    CRITICAL_SECTION csHistory;
    CRITICAL_SECTION csConfig;
    CRITICAL_SECTION csBalloon;
    NOTIFYICONDATA nid;
    HANDLE hMutex;
    WCHAR exeDir[MAX_LONG_PATH];
    WCHAR sysDir32[MAX_LONG_PATH];
    WCHAR sysDir64[MAX_LONG_PATH];
    WCHAR sysDirDrivers[MAX_LONG_PATH];
    HANDLE hLogFile;
    volatile LONG systemResumed;
    BALLOON_COOLDOWN *balloonCooldown;
    ULONGLONG lastBalloonCleanupTick;
    ULONGLONG lastEncodingWarningTick;
    ULONGLONG lastClampWarningTick;
    ULONGLONG lastExcludeWarningTick;
    ULONGLONG lastLogFailWarningTick;
    CONFIG config;
    FILETIME configLastWrite;
    int configLoadFailed;
    PROCESS_HISTORY *history;
    HPOWERNOTIFY hPowerNotify;
    BOOL folderWritableChecked;
};

static GLOBAL g = {0};

// Function prototypes
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
BOOL AddTrayIcon(HWND hwnd);
BOOL RemoveTrayIcon(void);
void ShowPopupMenu(HWND hwnd);
DWORD WINAPI MonitorThread(LPVOID lpParam);
void LogEvent(BOOL isSuspicious, const WCHAR *exeName, DWORD pid, const WCHAR *reason,
              float cpu, size_t memMB, BOOL memValid, const WCHAR *path);
void LogMessageW(const WCHAR *format, ...);
void LogErrorW(const WCHAR *format, ...);
#define LogMessage LogMessageW
#define LogError LogErrorW
BOOL IsProcessExcluded(const WCHAR *nameW, const CONFIG *cfg, const WCHAR *path);
BOOL IsBuiltInExcluded(const WCHAR *fileName, const WCHAR *fullPath);
PROCESS_HISTORY *FindOrCreateHistory(DWORD pid);
void RemoveHistory(DWORD pid);
void CleanupHistory(void);
void ResetAllHistory(void);
float CalcCpuUsage(HANDLE hProcess, PROCESS_HISTORY *hist);
float CalcAverageCpuUsage(HANDLE hProcess);
BOOL IsWindowHungFast(HWND hWnd, DWORD hangTimeoutMs);
BOOL CALLBACK EnumHungWindowsProc(HWND hWnd, LPARAM lParam);
HUNG_PROCESS_NODE *BuildHungProcessList(DWORD hangTimeoutMs, DWORD maxHungWindows, HANDLE stopEvent);
void FreeHungProcessList(HUNG_PROCESS_NODE *head);
BOOL IsProcessHung(DWORD pid, HUNG_PROCESS_NODE *hungList);
void RotateLogIfNeeded(DWORD maxSizeBytes);
void Cleanup(void);
BOOL IsUserAdmin(void);
static void ShowStatusDialog(HWND hwnd);
BOOL LoadConfig(void);
void CreateDefaultConfig(void);
BOOL CheckConfigFileChanged(void);
void UpdateConfigLastWrite(void);
void GetProcessPathW(DWORD pid, WCHAR *pathBuf, DWORD bufSize);
BOOL NtPathToDosPath(const WCHAR *ntPath, WCHAR *dosPath, DWORD dosSize);
static WCHAR *TrimWhitespace(WCHAR *str);
void GetExeDirectory(void);
void GetSystemDirectories(void);
void ExtractFileNameFromPath(const WCHAR *fullPath, WCHAR *fileName, DWORD fileNameSize);
static BOOL OpenProcessForQuery(DWORD pid, HANDLE *phProcess, WCHAR *pathBuf, DWORD pathSize);
static BOOL TryTerminateProcess(DWORD pid, const WCHAR *exeName, int *attempts, int *logSent);
static void CheckNormalProcess(const PROCESSENTRY32W *pe, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList);
static void CheckSystemProcess(const PROCESSENTRY32W *pe, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList);
static void CheckProcess(const PROCESSENTRY32W *pe, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList);
static void ShowBalloon(const WCHAR *title, const WCHAR *text, DWORD infoFlags);
static void UpdateTrayTooltip(void);
static void EnsureLogFileOpen(void);
static void CloseLogFile(void);
static void WriteLogUTF8(const char *utf8Buffer);
static void OnPowerResume(void);
static BOOL ShouldShowBalloonForProcess(const WCHAR *processName);
static void PeriodicBalloonCleanup(void);
static BOOL MeasureProcessResources(HANDLE hProcess, PROCESS_HISTORY *hist, float *cpu, size_t *memMB, BOOL *memValid);
static void FormatReason(WCHAR *buffer, size_t bufSize, float cpu, DWORD cpuThreshold,
                         BOOL memValid, size_t memMB, DWORD memThreshold, BOOL hung);
static BOOL IsSystemDirectory(const WCHAR *fullPath);
static void HandleConfigReload(ULONGLONG *lastConfigCheck, ULONGLONG *lastConfigFailBalloon);
static void ProcessSnapshot(const CONFIG *localConfig);
static void SplitExcludeString(const WCHAR *input, WCHAR excludeList[MAX_EXCLUDE_COUNT][MAX_PATH_LEN], int *count, BOOL *hadWarning);
static void CheckProcessHungAndTerminate(PROCESS_HISTORY *hist, DWORD pid, const WCHAR *exeName, HUNG_PROCESS_NODE *hungList);
static void CheckProcessResourcesAndTerminate(PROCESS_HISTORY *hist, HANDLE hProcess, DWORD pid, const WCHAR *exeName,
                                              const WCHAR *path, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList);
static void CleanupBalloonCooldown(void);
static void SafeLogMessageAfterUnlock(const WCHAR *format, ...);
static void CleanupTemporaryLogFile(void);
static void DeleteTemporaryLogFile(void);
static BOOL IsWindowsVersionSupported(void);
static void OpenManual(HWND hwnd);
static void CreateReadmeIfManualMissing(void);
static void CheckFolderWritable(void);

// Helper to get error description
static const WCHAR *GetErrorDescription(DWORD err)
{
    static WCHAR buf[256];
    buf[0] = L'\0';
    FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                   NULL, err, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                   buf, 256, NULL);
    size_t len = wcslen(buf);
    if (len > 0 && (buf[len - 1] == L'\n' || buf[len - 1] == L'\r'))
    {
        buf[len - 1] = L'\0';
    }
    if (len > 1 && (buf[len - 2] == L'\n' || buf[len - 2] == L'\r'))
    {
        buf[len - 2] = L'\0';
    }
    return buf;
}

// -------------------- Entry Point --------------------
int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLine, int nCmdShow)
{
    // Force detach any console that might be inherited (for MinGW compatibility)
    FreeConsole();

    if (!IsWindowsVersionSupported())
    {
        MessageBox(NULL, L"This program requires Windows Vista or later.\nPlease upgrade your operating system.", L"Unsupported OS", MB_OK | MB_ICONERROR);
        return 1;
    }

    INITCOMMONCONTROLSEX icc = {sizeof(INITCOMMONCONTROLSEX), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&icc);

    memset(&g, 0, sizeof(g));
    g.hLogFile = INVALID_HANDLE_VALUE;
    g.programRunning = 1;
    g.lastEncodingWarningTick = 0;
    g.lastClampWarningTick = 0;
    g.lastExcludeWarningTick = 0;
    g.lastLogFailWarningTick = 0;
    g.folderWritableChecked = FALSE;

    g.hInst = hInstance;

    GetExeDirectory();
    GetSystemDirectories();

    CleanupTemporaryLogFile();

    CreateReadmeIfManualMissing();
    CheckFolderWritable();

    g.hMutex = CreateMutex(NULL, TRUE, L"Local\\ProcessMonitor_SingleInstance");
    if (g.hMutex == NULL)
    {
        MessageBox(NULL, L"Failed to create mutex. Program will exit.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }
    if (GetLastError() == ERROR_ALREADY_EXISTS)
    {
        MessageBox(NULL, L"Process Monitor is already running in this user session.", L"Info", MB_OK | MB_ICONINFORMATION);
        CloseHandle(g.hMutex);
        return 0;
    }

    if (!IsUserAdmin())
    {
        MessageBox(NULL, L"This program needs administrator privileges to terminate other processes.\nIf you cannot terminate processes, please right-click the program and select 'Run as administrator'.", L"Important", MB_OK | MB_ICONWARNING);
    }

    InitializeCriticalSectionAndSpinCount(&g.csLog, CRITICAL_SECTION_SPIN_COUNT);
    InitializeCriticalSectionAndSpinCount(&g.csHistory, CRITICAL_SECTION_SPIN_COUNT);
    InitializeCriticalSectionAndSpinCount(&g.csConfig, CRITICAL_SECTION_SPIN_COUNT);
    InitializeCriticalSectionAndSpinCount(&g.csBalloon, CRITICAL_SECTION_SPIN_COUNT);

    BOOL configLoaded = LoadConfig();
    if (!configLoaded)
    {
        CreateDefaultConfig();
        configLoaded = LoadConfig();
        if (!configLoaded)
        {
            CONFIG defaultConfig;
            defaultConfig.monitorIntervalMs = DEFAULT_MONITOR_INTERVAL_MS;
            defaultConfig.cpuThresholdPercent = DEFAULT_CPU_THRESHOLD_PERCENT;
            defaultConfig.memThresholdMb = DEFAULT_MEM_THRESHOLD_MB;
            defaultConfig.hangTimeoutMs = DEFAULT_HANG_TIMEOUT_MS;
            defaultConfig.logMaxSizeBytes = DEFAULT_LOG_MAX_SIZE_BYTES;
            defaultConfig.maxHungWindows = DEFAULT_MAX_HUNG_WINDOWS;
            defaultConfig.notifyOnTermination = DEFAULT_NOTIFY_ON_TERMINATION;
            defaultConfig.excludeCount = 0;
            defaultConfig.monitoringDefault = 1;
            EnterCriticalSection(&g.csConfig);
            g.config = defaultConfig;
            g.configLoadFailed = 1;
            LeaveCriticalSection(&g.csConfig);
            LogMessage(L"Using default configuration (failed to load config.ini)");
            ShowBalloon(L"Configuration Error", L"Failed to load config.ini. Using default settings. Please check the file format.", NIIF_WARNING);
        }
    }
    UpdateConfigLastWrite();

    InterlockedExchange(&g.monitorActive, g.config.monitoringDefault ? 1 : 0);

    g.hStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
    if (!g.hStopEvent)
    {
        LogError(L"Failed to create stop event");
        goto cleanup;
    }

    WNDCLASS wc = {0};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);
    wc.lpszClassName = L"ProcessMonitorClass";
    if (!RegisterClass(&wc))
    {
        LogError(L"RegisterClass failed");
        goto cleanup;
    }

    g.hWnd = CreateWindow(L"ProcessMonitorClass", L"ProcessMonitor", WS_OVERLAPPEDWINDOW,
                          CW_USEDEFAULT, CW_USEDEFAULT, 300, 200, NULL, NULL, hInstance, NULL);
    if (!g.hWnd)
    {
        LogError(L"CreateWindow failed");
        goto cleanup;
    }

    if (!AddTrayIcon(g.hWnd))
    {
        LogError(L"Failed to add tray icon");
        DestroyWindow(g.hWnd);
        goto cleanup;
    }

    WCHAR startupMsg[128];
    swprintf(startupMsg, 128, L"Process Monitor started. Monitoring is %s.",
             InterlockedCompareExchange(&g.monitorActive, 0, 0) ? L"ON" : L"OFF");
    ShowBalloon(L"Process Monitor", startupMsg, NIIF_INFO);

    g.hMonitorThread = CreateThread(NULL, 0, MonitorThread, NULL, 0, NULL);
    if (!g.hMonitorThread)
    {
        LogError(L"CreateThread failed");
        RemoveTrayIcon();
        DestroyWindow(g.hWnd);
        goto cleanup;
    }

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0))
    {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

cleanup:
    Cleanup();
    if (g.hStopEvent)
        CloseHandle(g.hStopEvent);
    if (g.hMutex)
        CloseHandle(g.hMutex);
    return 0;
}

// -------------------- Window Procedure --------------------
LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg)
    {
    case WM_CREATE:
        g.hPowerNotify = RegisterPowerSettingNotification(hWnd, &GUID_SESSION_DISPLAY_STATUS, DEVICE_NOTIFY_WINDOW_HANDLE);
        break;

    case WM_POWERBROADCAST:
        if (wParam == PBT_APMRESUMEAUTOMATIC || wParam == PBT_APMRESUMESUSPEND ||
            wParam == PBT_APMRESUMECRITICAL || wParam == PBT_APMRESUMEHIBERNATE)
        {
            OnPowerResume();
        }
        break;

    case WM_TRAYICON:
        if (lParam == WM_LBUTTONDBLCLK)
        {
            ShowStatusDialog(hWnd);
        }
        else if (lParam == WM_RBUTTONUP)
        {
            ShowPopupMenu(hWnd);
        }
        break;

    case WM_COMMAND:
        switch (LOWORD(wParam))
        {
        case IDM_START:
            InterlockedExchange(&g.monitorActive, 1);
            ShowBalloon(L"Process Monitor", L"Monitoring started", NIIF_INFO);
            UpdateTrayTooltip();
            break;
        case IDM_STOP:
            InterlockedExchange(&g.monitorActive, 0);
            ShowBalloon(L"Process Monitor", L"Monitoring stopped", NIIF_INFO);
            UpdateTrayTooltip();
            break;
        case IDM_VIEWLOG:
        {
            WCHAR logPath[MAX_LONG_PATH];
            wcscpy_s(logPath, MAX_LONG_PATH, g.exeDir);
            wcscat_s(logPath, MAX_LONG_PATH, L"\\");
            wcscat_s(logPath, MAX_LONG_PATH, LOG_FILE);
            ShellExecuteW(hWnd, L"open", logPath, NULL, NULL, SW_SHOW);
            break;
        }
        case IDM_VIEWCONFIG:
        {
            WCHAR configPath[MAX_LONG_PATH];
            wcscpy_s(configPath, MAX_LONG_PATH, g.exeDir);
            wcscat_s(configPath, MAX_LONG_PATH, L"\\");
            wcscat_s(configPath, MAX_LONG_PATH, CONFIG_FILE);
            ShellExecuteW(hWnd, L"open", configPath, NULL, NULL, SW_SHOW);
            break;
        }
        case IDM_VIEWMANUAL:
            OpenManual(hWnd);
            break;
        case IDM_EXIT:
            DestroyWindow(hWnd);
            break;
        }
        break;

    case WM_DESTROY:
        if (g.hPowerNotify)
        {
            UnregisterPowerSettingNotification(g.hPowerNotify);
            g.hPowerNotify = NULL;
        }
        RemoveTrayIcon();
        PostQuitMessage(0);
        break;

    default:
        return DefWindowProc(hWnd, msg, wParam, lParam);
    }
    return 0;
}

// -------------------- Tray Icon Functions --------------------
BOOL AddTrayIcon(HWND hwnd)
{
    memset(&g.nid, 0, sizeof(NOTIFYICONDATA));
    g.nid.cbSize = sizeof(NOTIFYICONDATA);
    g.nid.hWnd = hwnd;
    g.nid.uID = 1;
    g.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    g.nid.uCallbackMessage = WM_TRAYICON;

    // Always use default icon
    g.nid.hIcon = LoadIcon(NULL, IDI_APPLICATION);

    UpdateTrayTooltip();

    return Shell_NotifyIcon(NIM_ADD, &g.nid);
}

BOOL RemoveTrayIcon(void)
{
    return Shell_NotifyIcon(NIM_DELETE, &g.nid);
}

static void UpdateTrayTooltip(void)
{
    WCHAR tip[256];
    swprintf(tip, 256, L"Process Monitor v%s - %s", VERSION_STRING,
             InterlockedCompareExchange(&g.monitorActive, 0, 0) ? L"Running" : L"Stopped");
    wcsncpy_s(g.nid.szTip, 128, tip, _TRUNCATE);
    g.nid.uFlags = NIF_TIP;
    Shell_NotifyIcon(NIM_MODIFY, &g.nid);
    g.nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
}

void ShowPopupMenu(HWND hwnd)
{
    HMENU hMenu = CreatePopupMenu();
    AppendMenu(hMenu, MF_STRING | (InterlockedCompareExchange(&g.monitorActive, 0, 0) ? MF_CHECKED : 0), IDM_START, L"Start Monitoring");
    AppendMenu(hMenu, MF_STRING | (InterlockedCompareExchange(&g.monitorActive, 0, 0) ? 0 : MF_CHECKED), IDM_STOP, L"Stop Monitoring");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_VIEWLOG, L"View Log");
    AppendMenu(hMenu, MF_STRING, IDM_VIEWCONFIG, L"Edit Config");
    AppendMenu(hMenu, MF_STRING, IDM_VIEWMANUAL, L"View Manual");
    AppendMenu(hMenu, MF_SEPARATOR, 0, NULL);
    AppendMenu(hMenu, MF_STRING, IDM_EXIT, L"Exit");

    POINT pt;
    GetCursorPos(&pt);
    SetForegroundWindow(hwnd);
    TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
    DestroyMenu(hMenu);
}

// -------------------- Open Manual --------------------
static void OpenManual(HWND hwnd)
{
    WCHAR manualPath[MAX_LONG_PATH];
    wcscpy_s(manualPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(manualPath, MAX_LONG_PATH, L"\\");
    wcscat_s(manualPath, MAX_LONG_PATH, MANUAL_FILE);

    DWORD attr = GetFileAttributesW(manualPath);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        ShellExecuteW(hwnd, L"open", manualPath, NULL, NULL, SW_SHOW);
    }
    else
    {
        MessageBoxW(hwnd, L"Manual file (monitor_manual.txt) not found.\nPlease re-download the program package to get the full manual.", L"Manual Missing", MB_OK | MB_ICONWARNING);
    }
}

// -------------------- Create README if Manual Missing --------------------
static void CreateReadmeIfManualMissing(void)
{
    WCHAR manualPath[MAX_LONG_PATH];
    wcscpy_s(manualPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(manualPath, MAX_LONG_PATH, L"\\");
    wcscat_s(manualPath, MAX_LONG_PATH, MANUAL_FILE);

    DWORD attr = GetFileAttributesW(manualPath);
    if (attr != INVALID_FILE_ATTRIBUTES && !(attr & FILE_ATTRIBUTE_DIRECTORY))
    {
        return;
    }

    WCHAR readmePath[MAX_LONG_PATH];
    wcscpy_s(readmePath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(readmePath, MAX_LONG_PATH, L"\\");
    wcscat_s(readmePath, MAX_LONG_PATH, README_FILE);

    FILE *f = _wfopen(readmePath, L"w");
    if (f)
    {
        fprintf(f, "========================================\n");
        fprintf(f, "Process Monitor - Quick Start Guide\n");
        fprintf(f, "========================================\n\n");
        fprintf(f, "The full manual (monitor_manual.txt) is missing.\n");
        fprintf(f, "Please download the complete program package to get the detailed manual.\n\n");
        fprintf(f, "Basic usage:\n");
        fprintf(f, "- Right-click the tray icon to start/stop monitoring.\n");
        fprintf(f, "- Double-click the tray icon to open status dialog.\n");
        fprintf(f, "- Edit config.ini to adjust settings.\n");
        fprintf(f, "- View monitor.log for recorded events.\n\n");
        fprintf(f, "For more information, please re-download the program.\n");
        fclose(f);
    }
}

// -------------------- Check Folder Writable --------------------
static void CheckFolderWritable(void)
{
    if (g.folderWritableChecked)
        return;
    g.folderWritableChecked = TRUE;

    WCHAR testPath[MAX_LONG_PATH];
    wcscpy_s(testPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(testPath, MAX_LONG_PATH, L"\\writetest.tmp");

    HANDLE hFile = CreateFileW(testPath, GENERIC_WRITE, 0, NULL,
                               CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        MessageBoxW(NULL, L"Warning: The program folder is not writable.\nConfiguration and log files may not be saved.\nPlease run the program from a writable location or run as administrator.", L"Folder Permission", MB_OK | MB_ICONWARNING);
    }
    else
    {
        CloseHandle(hFile);
    }
}

// -------------------- Balloon Cooldown Management --------------------
static BOOL ShouldShowBalloonForProcess(const WCHAR *processName)
{
    if (processName == NULL || processName[0] == L'\0')
        return FALSE;

    ULONGLONG now = GetTickCount64();
    EnterCriticalSection(&g.csBalloon);

    BALLOON_COOLDOWN *curr = g.balloonCooldown;
    while (curr)
    {
        if (_wcsicmp(curr->processName, processName) == 0)
        {
            if (now - curr->lastTick < SUSPICIOUS_BALLOON_COOLDOWN_MS)
            {
                LeaveCriticalSection(&g.csBalloon);
                return FALSE;
            }
            curr->lastTick = now;
            LeaveCriticalSection(&g.csBalloon);
            return TRUE;
        }
        curr = curr->next;
    }

    BALLOON_COOLDOWN *newNode = (BALLOON_COOLDOWN *)malloc(sizeof(BALLOON_COOLDOWN));
    if (newNode)
    {
        wcsncpy_s(newNode->processName, MAX_PATH_LEN, processName, _TRUNCATE);
        newNode->lastTick = now;
        newNode->next = g.balloonCooldown;
        g.balloonCooldown = newNode;
    }
    LeaveCriticalSection(&g.csBalloon);
    return TRUE;
}

static void PeriodicBalloonCleanup(void)
{
    ULONGLONG now = GetTickCount64();
    if (now - g.lastBalloonCleanupTick < BALLOON_CLEANUP_INTERVAL_MS)
        return;

    EnterCriticalSection(&g.csBalloon);
    BALLOON_COOLDOWN **prev = &g.balloonCooldown;
    BALLOON_COOLDOWN *curr = g.balloonCooldown;
    while (curr)
    {
        if (now - curr->lastTick > SUSPICIOUS_BALLOON_COOLDOWN_MS)
        {
            *prev = curr->next;
            free(curr);
            curr = *prev;
        }
        else
        {
            prev = &curr->next;
            curr = curr->next;
        }
    }
    g.lastBalloonCleanupTick = now;
    LeaveCriticalSection(&g.csBalloon);
}

static void CleanupBalloonCooldown(void)
{
    EnterCriticalSection(&g.csBalloon);
    BALLOON_COOLDOWN *curr = g.balloonCooldown;
    while (curr)
    {
        BALLOON_COOLDOWN *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    g.balloonCooldown = NULL;
    LeaveCriticalSection(&g.csBalloon);
}

// -------------------- Power Resume Handling --------------------
static void OnPowerResume(void)
{
    InterlockedExchange(&g.systemResumed, 1);
    LogMessage(L"System resume detected, resetting process history.");
}

// -------------------- NT Path to DOS Path Conversion --------------------
BOOL NtPathToDosPath(const WCHAR *ntPath, WCHAR *dosPath, DWORD dosSize)
{
    if (!ntPath || !dosPath || dosSize == 0)
        return FALSE;

    WCHAR drives[256];
    DWORD len = GetLogicalDriveStringsW(256, drives);
    if (len == 0 || len > 256)
        return FALSE;

    WCHAR *drive = drives;
    while (*drive)
    {
        WCHAR driveRoot[4] = {drive[0], drive[1], L'\\', L'\0'};
        WCHAR targetPath[INTERNAL_PATH_BUFFER_SIZE];
        if (QueryDosDeviceW(driveRoot, targetPath, INTERNAL_PATH_BUFFER_SIZE))
        {
            size_t targetLen = wcslen(targetPath);
            if (_wcsnicmp(ntPath, targetPath, targetLen) == 0)
            {
                _snwprintf_s(dosPath, dosSize, _TRUNCATE, L"%s%s", driveRoot, ntPath + targetLen);
                return TRUE;
            }
        }
        drive += wcslen(drive) + 1;
    }
    return FALSE;
}

void GetProcessPathW(DWORD pid, WCHAR *pathBuf, DWORD bufSize)
{
    WCHAR internalPath[INTERNAL_PATH_BUFFER_SIZE];
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProcess)
    {
        DWORD size = INTERNAL_PATH_BUFFER_SIZE;
        if (QueryFullProcessImageNameW(hProcess, 0, internalPath, &size))
        {
            wcsncpy_s(pathBuf, bufSize, internalPath, _TRUNCATE);
            CloseHandle(hProcess);
            return;
        }
        CloseHandle(hProcess);
    }

    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hProcess)
    {
        DWORD len = GetProcessImageFileNameW(hProcess, internalPath, INTERNAL_PATH_BUFFER_SIZE);
        if (len > 0)
        {
            WCHAR dosPath[INTERNAL_PATH_BUFFER_SIZE];
            if (NtPathToDosPath(internalPath, dosPath, INTERNAL_PATH_BUFFER_SIZE))
            {
                wcsncpy_s(pathBuf, bufSize, dosPath, _TRUNCATE);
            }
            else
            {
                wcsncpy_s(pathBuf, bufSize, internalPath, _TRUNCATE);
            }
        }
        else
        {
            pathBuf[0] = L'\0';
        }
        CloseHandle(hProcess);
    }
    else
    {
        pathBuf[0] = L'\0';
    }
}

void ExtractFileNameFromPath(const WCHAR *fullPath, WCHAR *fileName, DWORD fileNameSize)
{
    if (fullPath == NULL || fullPath[0] == L'\0')
    {
        fileName[0] = L'\0';
        return;
    }
    const WCHAR *p = wcsrchr(fullPath, L'\\');
    if (p == NULL)
        p = wcsrchr(fullPath, L'/');
    if (p != NULL)
    {
        wcsncpy_s(fileName, fileNameSize, p + 1, _TRUNCATE);
    }
    else
    {
        wcsncpy_s(fileName, fileNameSize, fullPath, _TRUNCATE);
    }
}

void GetSystemDirectories(void)
{
    WCHAR winDir[MAX_LONG_PATH];
    if (GetWindowsDirectoryW(winDir, MAX_LONG_PATH) == 0)
    {
        wcscpy_s(winDir, MAX_LONG_PATH, L"C:\\Windows");
    }

    wcscpy_s(g.sysDir32, MAX_LONG_PATH, winDir);
    wcscat_s(g.sysDir32, MAX_LONG_PATH, L"\\System32\\");

    if (GetSystemWow64DirectoryW(winDir, MAX_LONG_PATH) > 0)
    {
        wcscpy_s(g.sysDir64, MAX_LONG_PATH, winDir);
        wcscat_s(g.sysDir64, MAX_LONG_PATH, L"\\");
    }
    else
    {
        wcscpy_s(g.sysDir64, MAX_LONG_PATH, g.sysDir32);
    }

    wcscpy_s(g.sysDirDrivers, MAX_LONG_PATH, winDir);
    wcscat_s(g.sysDirDrivers, MAX_LONG_PATH, L"\\System32\\drivers\\");
}

static BOOL IsSystemDirectory(const WCHAR *fullPath)
{
    if (!fullPath || fullPath[0] == L'\0')
        return FALSE;
    size_t len32 = wcslen(g.sysDir32);
    if (_wcsnicmp(fullPath, g.sysDir32, len32) == 0)
        return TRUE;
    size_t len64 = wcslen(g.sysDir64);
    if (_wcsnicmp(fullPath, g.sysDir64, len64) == 0)
        return TRUE;
    size_t lenDrv = wcslen(g.sysDirDrivers);
    if (_wcsnicmp(fullPath, g.sysDirDrivers, lenDrv) == 0)
        return TRUE;
    return FALSE;
}

// -------------------- Process History Management --------------------
PROCESS_HISTORY *FindOrCreateHistory(DWORD pid)
{
    EnterCriticalSection(&g.csHistory);
    PROCESS_HISTORY **prev = &g.history;
    PROCESS_HISTORY *curr = g.history;
    while (curr)
    {
        if (curr->pid == pid)
        {
            curr->seen = TRUE;
            LeaveCriticalSection(&g.csHistory);
            return curr;
        }
        prev = &curr->next;
        curr = curr->next;
    }

    PROCESS_HISTORY *newHist = (PROCESS_HISTORY *)malloc(sizeof(PROCESS_HISTORY));
    if (newHist)
    {
        memset(newHist, 0, sizeof(PROCESS_HISTORY));
        newHist->pid = pid;
        newHist->seen = TRUE;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hProcess)
        {
            FILETIME ftCreate, ftExit, ftKernel, ftUser;
            if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
            {
                newHist->ftCreate = ftCreate;
                newHist->ftKernel = ftKernel;
                newHist->ftUser = ftUser;
                QueryPerformanceCounter(&newHist->perfTime);
            }
            CloseHandle(hProcess);
        }

        newHist->next = g.history;
        g.history = newHist;
    }
    LeaveCriticalSection(&g.csHistory);
    return newHist;
}

void RemoveHistory(DWORD pid)
{
    EnterCriticalSection(&g.csHistory);
    PROCESS_HISTORY **prev = &g.history;
    PROCESS_HISTORY *curr = g.history;
    while (curr)
    {
        if (curr->pid == pid)
        {
            *prev = curr->next;
            free(curr);
            break;
        }
        prev = &curr->next;
        curr = curr->next;
    }
    LeaveCriticalSection(&g.csHistory);
}

void CleanupHistory(void)
{
    EnterCriticalSection(&g.csHistory);
    PROCESS_HISTORY **prev = &g.history;
    PROCESS_HISTORY *curr = g.history;
    while (curr)
    {
        if (!curr->seen)
        {
            *prev = curr->next;
            free(curr);
            curr = *prev;
        }
        else
        {
            curr->seen = FALSE;
            prev = &curr->next;
            curr = curr->next;
        }
    }
    LeaveCriticalSection(&g.csHistory);
}

void ResetAllHistory(void)
{
    EnterCriticalSection(&g.csHistory);
    PROCESS_HISTORY *curr = g.history;
    while (curr)
    {
        PROCESS_HISTORY *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    g.history = NULL;
    LeaveCriticalSection(&g.csHistory);
}

// -------------------- CPU Usage Calculation (using QPC) --------------------
float CalcCpuUsage(HANDLE hProcess, PROCESS_HISTORY *hist)
{
    if (hProcess == NULL)
        return -1.0f;
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
    {
        return -1.0f;
    }

    LARGE_INTEGER nowPerf;
    QueryPerformanceCounter(&nowPerf);

    ULARGE_INTEGER k1, u1, k2, u2;
    k1.LowPart = hist->ftKernel.dwLowDateTime;
    k1.HighPart = hist->ftKernel.dwHighDateTime;
    u1.LowPart = hist->ftUser.dwLowDateTime;
    u1.HighPart = hist->ftUser.dwHighDateTime;

    k2.LowPart = ftKernel.dwLowDateTime;
    k2.HighPart = ftKernel.dwHighDateTime;
    u2.LowPart = ftUser.dwLowDateTime;
    u2.HighPart = ftUser.dwHighDateTime;

    ULONGLONG timeDelta = (k2.QuadPart - k1.QuadPart) + (u2.QuadPart - u1.QuadPart);
    if (timeDelta == 0)
        return 0.0f;

    LARGE_INTEGER perfFreq;
    QueryPerformanceFrequency(&perfFreq);
    double seconds = (double)(nowPerf.QuadPart - hist->perfTime.QuadPart) / (double)perfFreq.QuadPart;
    if (seconds <= 0.0)
        return 0.0f;

    double cpuPercent = (timeDelta / 10000.0) / seconds / 10.0;

    hist->ftKernel = ftKernel;
    hist->ftUser = ftUser;
    hist->perfTime = nowPerf;

    return (float)cpuPercent;
}

float CalcAverageCpuUsage(HANDLE hProcess)
{
    if (hProcess == NULL)
        return -1.0f;
    FILETIME ftCreate, ftExit, ftKernel, ftUser;
    if (!GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser))
    {
        return -1.0f;
    }

    ULARGE_INTEGER create, kernel, user;
    create.LowPart = ftCreate.dwLowDateTime;
    create.HighPart = ftCreate.dwHighDateTime;
    kernel.LowPart = ftKernel.dwLowDateTime;
    kernel.HighPart = ftKernel.dwHighDateTime;
    user.LowPart = ftUser.dwLowDateTime;
    user.HighPart = ftUser.dwHighDateTime;

    ULONGLONG totalTime = kernel.QuadPart + user.QuadPart;
    FILETIME nowFt;
    GetSystemTimeAsFileTime(&nowFt);
    ULARGE_INTEGER now;
    now.LowPart = nowFt.dwLowDateTime;
    now.HighPart = nowFt.dwHighDateTime;
    ULONGLONG age = now.QuadPart - create.QuadPart;
    if (age == 0)
        return 0.0f;

    double cpuPercent = (totalTime / 10000.0) / (age / 10000000.0) / 10.0;
    return (float)cpuPercent;
}

// -------------------- Hung Window Detection --------------------
BOOL IsWindowHungFast(HWND hWnd, DWORD hangTimeoutMs)
{
    DWORD_PTR result;
    LRESULT res = SendMessageTimeoutW(hWnd, WM_NULL, 0, 0, SMTO_ABORTIFHUNG | SMTO_NORMAL, hangTimeoutMs, &result);
    return (res == 0);
}

BOOL CALLBACK EnumHungWindowsProc(HWND hWnd, LPARAM lParam)
{
    ENUM_HUNG_PARAMS *params = (ENUM_HUNG_PARAMS *)lParam;
    if (params->scannedCount >= params->maxWindows)
    {
        LogMessage(L"WARNING: Reached maximum number of windows to check (MaxHungWindows=%lu). Some windows may not be checked. Consider increasing this value in config.ini if you have many windows.", params->maxWindows);
        return FALSE;
    }
    if (WaitForSingleObject(params->stopEvent, 0) == WAIT_OBJECT_0)
    {
        return FALSE;
    }

    if (!IsWindowVisible(hWnd))
        return TRUE;

    DWORD pid;
    GetWindowThreadProcessId(hWnd, &pid);
    if (pid == 0)
        return TRUE;

    if (IsWindowHungFast(hWnd, params->hangTimeoutMs))
    {
        HUNG_PROCESS_NODE *curr = *(params->head);
        while (curr)
        {
            if (curr->pid == pid)
                return TRUE;
            curr = curr->next;
        }
        HUNG_PROCESS_NODE *node = (HUNG_PROCESS_NODE *)malloc(sizeof(HUNG_PROCESS_NODE));
        if (node)
        {
            node->pid = pid;
            node->next = *(params->head);
            *(params->head) = node;
        }
        else
        {
            LogError(L"Failed to allocate memory for hung process node (PID %u)", pid);
        }
    }
    params->scannedCount++;
    return TRUE;
}

HUNG_PROCESS_NODE *BuildHungProcessList(DWORD hangTimeoutMs, DWORD maxHungWindows, HANDLE stopEvent)
{
    HUNG_PROCESS_NODE *head = NULL;
    ENUM_HUNG_PARAMS params;
    params.head = &head;
    params.hangTimeoutMs = hangTimeoutMs;
    params.maxWindows = maxHungWindows;
    params.scannedCount = 0;
    params.stopEvent = stopEvent;
    EnumWindows(EnumHungWindowsProc, (LPARAM)&params);
    return head;
}

void FreeHungProcessList(HUNG_PROCESS_NODE *head)
{
    while (head)
    {
        HUNG_PROCESS_NODE *tmp = head;
        head = head->next;
        free(tmp);
    }
}

BOOL IsProcessHung(DWORD pid, HUNG_PROCESS_NODE *hungList)
{
    while (hungList)
    {
        if (hungList->pid == pid)
            return TRUE;
        hungList = hungList->next;
    }
    return FALSE;
}

// -------------------- Logging with UTF-8 --------------------
static void EnsureLogFileOpen(void)
{
    if (g.hLogFile != INVALID_HANDLE_VALUE)
        return;

    WCHAR logPath[MAX_LONG_PATH];
    wcscpy_s(logPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(logPath, MAX_LONG_PATH, L"\\");
    wcscat_s(logPath, MAX_LONG_PATH, LOG_FILE);

    g.hLogFile = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                             OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (g.hLogFile != INVALID_HANDLE_VALUE)
    {
        SetFilePointer(g.hLogFile, 0, NULL, FILE_END);
    }
    else
    {
        ULONGLONG now = GetTickCount64();
        if (now - g.lastLogFailWarningTick >= LOG_FAIL_BALLOON_COOLDOWN_MS)
        {
            ShowBalloon(L"Log Error", L"Failed to create log file. Please check disk space and write permissions.", NIIF_WARNING);
            g.lastLogFailWarningTick = now;
        }
    }
}

static void CloseLogFile(void)
{
    if (g.hLogFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(g.hLogFile);
        g.hLogFile = INVALID_HANDLE_VALUE;
    }
}

static void WriteLogUTF8(const char *utf8Buffer)
{
    if (utf8Buffer == NULL)
        return;

    EnterCriticalSection(&g.csLog);
    EnsureLogFileOpen();
    if (g.hLogFile == INVALID_HANDLE_VALUE)
    {
        LeaveCriticalSection(&g.csLog);
        return;
    }

    DWORD bytesWritten;
    DWORD delays[] = {100, 200, 400, 800, 1600};
    for (int retry = 0; retry < 5; retry++)
    {
        if (WriteFile(g.hLogFile, utf8Buffer, (DWORD)strlen(utf8Buffer), &bytesWritten, NULL))
        {
            break;
        }
        DWORD err = GetLastError();
        if (err == ERROR_DISK_FULL || err == ERROR_HANDLE_DISK_FULL)
        {
            ULONGLONG now = GetTickCount64();
            if (now - g.lastLogFailWarningTick >= LOG_FAIL_BALLOON_COOLDOWN_MS)
            {
                ShowBalloon(L"Log Error", L"Disk space full. Log may not be written.", NIIF_WARNING);
                g.lastLogFailWarningTick = now;
            }
        }
        if (InterlockedCompareExchange(&g.programRunning, 1, 1) != 1)
        {
            break;
        }
        if (retry < 4)
            Sleep(delays[retry]);
    }
    LeaveCriticalSection(&g.csLog);
}

void LogMessageW(const WCHAR *format, ...)
{
    WCHAR wideBuf[4096];
    va_list args;
    va_start(args, format);
    vswprintf(wideBuf, 4096, format, args);
    va_end(args);

    SYSTEMTIME st;
    GetLocalTime(&st);
    WCHAR timeBuf[64];
    swprintf(timeBuf, 64, L"[%04d-%02d-%02d %02d:%02d:%02d] ",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

    WCHAR finalWide[4160];
    wcscpy_s(finalWide, 4160, timeBuf);
    wcscat_s(finalWide, 4160, wideBuf);
    wcscat_s(finalWide, 4160, L"\n");

    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, finalWide, -1, NULL, 0, NULL, NULL);
    if (utf8Len > 0)
    {
        char *utf8Buf = (char *)malloc(utf8Len);
        if (utf8Buf)
        {
            WideCharToMultiByte(CP_UTF8, 0, finalWide, -1, utf8Buf, utf8Len, NULL, NULL);
            WriteLogUTF8(utf8Buf);
            free(utf8Buf);
        }
    }
}

void LogErrorW(const WCHAR *format, ...)
{
    WCHAR wideBuf[4096];
    va_list args;
    va_start(args, format);
    vswprintf(wideBuf, 4096, format, args);
    va_end(args);

    DWORD err = GetLastError();
    const WCHAR *errDesc = GetErrorDescription(err);
    WCHAR errBuf[512];
    swprintf(errBuf, 512, L" [Error %lu: %s]", err, errDesc);

    WCHAR full[4224];
    wcscpy_s(full, 4224, wideBuf);
    wcscat_s(full, 4224, errBuf);
    LogMessageW(L"%s", full);
}

void LogEvent(BOOL isSuspicious, const WCHAR *exeName, DWORD pid, const WCHAR *reason,
              float cpu, size_t memMB, BOOL memValid, const WCHAR *path)
{
    WCHAR memStr[32];
    if (memValid)
    {
        swprintf(memStr, 32, L"%llu MB", (unsigned long long)memMB);
    }
    else
    {
        wcscpy_s(memStr, 32, L"N/A");
    }

    WCHAR cpuStr[32];
    swprintf(cpuStr, 32, L"%.1f%%", cpu);

    WCHAR pathBuf[INTERNAL_PATH_BUFFER_SIZE];
    if (path && path[0] != L'\0')
    {
        wcscpy_s(pathBuf, INTERNAL_PATH_BUFFER_SIZE, path);
    }
    else
    {
        wcscpy_s(pathBuf, INTERNAL_PATH_BUFFER_SIZE, L"Path unavailable");
    }

    if (isSuspicious)
    {
        LogMessage(L"SUSPICIOUS SYSTEM PROCESS: %ls (PID %u)\n  Reason: %ls\n  CPU: %ls  Memory: %ls\n  Path: %ls\n  This may indicate malware infection. (If this is normal system activity, you can ignore this warning.)",
                   exeName, pid, reason, cpuStr, memStr, pathBuf);
    }
    else
    {
        LogMessage(L"Terminated process: %ls (PID %u)\n  Reason: %ls\n  CPU: %ls  Memory: %ls\n  Path: %ls",
                   exeName, pid, reason, cpuStr, memStr, pathBuf);
        CONFIG cfg;
        EnterCriticalSection(&g.csConfig);
        cfg = g.config;
        LeaveCriticalSection(&g.csConfig);
        if (cfg.notifyOnTermination)
        {
            WCHAR balloonText[512];
            swprintf(balloonText, 512, L"Terminated %ls (PID %u)\nReason: %ls", exeName, pid, reason);
            ShowBalloon(L"Process Terminated", balloonText, NIIF_INFO);
        }
    }
}

static void SafeLogMessageAfterUnlock(const WCHAR *format, ...)
{
    va_list args;
    va_start(args, format);
    WCHAR wideBuf[4096];
    vswprintf(wideBuf, 4096, format, args);
    va_end(args);
    LogMessageW(L"%s", wideBuf);
}

void RotateLogIfNeeded(DWORD maxSizeBytes)
{
    EnterCriticalSection(&g.csLog);
    if (g.hLogFile == INVALID_HANDLE_VALUE)
    {
        LeaveCriticalSection(&g.csLog);
        return;
    }

    LARGE_INTEGER fileSize;
    if (!GetFileSizeEx(g.hLogFile, &fileSize))
    {
        LeaveCriticalSection(&g.csLog);
        return;
    }
    if (fileSize.QuadPart <= (LONGLONG)maxSizeBytes)
    {
        LeaveCriticalSection(&g.csLog);
        return;
    }

    CloseLogFile();

    WCHAR logPath[MAX_LONG_PATH];
    wcscpy_s(logPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(logPath, MAX_LONG_PATH, L"\\");
    wcscat_s(logPath, MAX_LONG_PATH, LOG_FILE);

    WCHAR oldPath[MAX_LONG_PATH];
    wcscpy_s(oldPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(oldPath, MAX_LONG_PATH, L"\\");
    wcscat_s(oldPath, MAX_LONG_PATH, LOG_FILE_OLD);

    WCHAR tempPath[MAX_LONG_PATH];
    wcscpy_s(tempPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(tempPath, MAX_LONG_PATH, L"\\");
    wcscat_s(tempPath, MAX_LONG_PATH, LOG_TEMP_FILE);

    _wremove(oldPath);
    _wremove(tempPath);

    BOOL renamed = FALSE;
    int retry;
    for (retry = 0; retry < LOG_RENAME_RETRY_LIMIT; retry++)
    {
        if (_wrename(logPath, tempPath) == 0)
        {
            if (_wrename(tempPath, oldPath) == 0)
            {
                renamed = TRUE;
                break;
            }
            else
            {
                _wrename(tempPath, logPath);
            }
        }
        if (retry < LOG_RENAME_RETRY_LIMIT - 1)
            Sleep(LOG_RENAME_DELAYS[retry]);
    }

    LeaveCriticalSection(&g.csLog);

    if (!renamed)
    {
        SafeLogMessageAfterUnlock(L"WARNING: Log rotation failed after %d attempts; attempting to truncate.", LOG_RENAME_RETRY_LIMIT);
        ShowBalloon(L"Log Rotation Failed", L"Log file may be locked by another program (e.g., Notepad). Please close any program that might be using monitor.log and try again. If the problem persists, restart your computer.", NIIF_WARNING);
        HANDLE hFile = CreateFileW(logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
                                   OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE)
        {
            SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
            SetEndOfFile(hFile);
            CloseHandle(hFile);
            SafeLogMessageAfterUnlock(L"Log file truncated successfully.");
        }
        else
        {
            SafeLogMessageAfterUnlock(L"ERROR: Failed to truncate log file. Log may continue to grow.");
        }
    }
    else
    {
        SafeLogMessageAfterUnlock(L"Log rotated successfully.");
    }

    EnterCriticalSection(&g.csLog);
    EnsureLogFileOpen();
    LeaveCriticalSection(&g.csLog);
}

// -------------------- Helper Functions for Process Checking --------------------
static BOOL OpenProcessForQuery(DWORD pid, HANDLE *phProcess, WCHAR *pathBuf, DWORD pathSize)
{
    *phProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (*phProcess == NULL)
    {
        *phProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    }
    if (*phProcess == NULL)
    {
        GetProcessPathW(pid, pathBuf, pathSize);
        return FALSE;
    }
    DWORD size = pathSize;
    BOOL success = QueryFullProcessImageNameW(*phProcess, 0, pathBuf, &size);
    if (!success)
    {
        GetProcessPathW(pid, pathBuf, pathSize);
    }
    return TRUE;
}

static BOOL MeasureProcessResources(HANDLE hProcess, PROCESS_HISTORY *hist, float *cpu, size_t *memMB, BOOL *memValid)
{
    *cpu = CalcCpuUsage(hProcess, hist);
    if (*cpu < 0)
    {
        *cpu = 0;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
    {
        *memMB = pmc.WorkingSetSize / (1024 * 1024);
        *memValid = TRUE;
    }
    else
    {
        *memMB = 0;
        *memValid = FALSE;
    }
    return TRUE;
}

static void FormatReason(WCHAR *buffer, size_t bufSize, float cpu, DWORD cpuThreshold,
                         BOOL memValid, size_t memMB, DWORD memThreshold, BOOL hung)
{
    buffer[0] = L'\0';
    if (cpu > cpuThreshold)
    {
        swprintf(buffer, bufSize, L"High CPU: %.1f%% (threshold %lu%%)", cpu, cpuThreshold);
    }
    else if (memValid && memMB > memThreshold)
    {
        swprintf(buffer, bufSize, L"High memory: %llu MB (threshold %lu MB)", (unsigned long long)memMB, memThreshold);
    }
    else if (hung)
    {
        swprintf(buffer, bufSize, L"Window not responding");
    }
}

static BOOL TryTerminateProcess(DWORD pid, const WCHAR *exeName, int *attempts, int *logSent)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL)
    {
        DWORD err = GetLastError();
        const WCHAR *desc = GetErrorDescription(err);
        LogMessage(L"Failed to open process %ls (PID %u) for termination: %ls (Error %lu)", exeName, pid, desc, err);
        static BOOL accessDeniedShown = FALSE;
        if (err == ERROR_ACCESS_DENIED && !accessDeniedShown)
        {
            accessDeniedShown = TRUE;
            ShowBalloon(L"Permission Notice", L"Some processes could not be terminated due to insufficient privileges. For full functionality, please run the program as administrator.", NIIF_WARNING);
        }
        return FALSE;
    }
    if (TerminateProcess(hProcess, 1))
    {
        LogMessage(L"Successfully terminated process %ls (PID %u)", exeName, pid);
        CloseHandle(hProcess);
        return TRUE;
    }
    else
    {
        DWORD err = GetLastError();
        const WCHAR *desc = GetErrorDescription(err);
        LogMessage(L"Failed to terminate process %ls (PID %u): %ls (Error %lu)", exeName, pid, desc, err);
        CloseHandle(hProcess);
        if (attempts)
            (*attempts)++;
        if (logSent && *logSent == 0 && attempts && *attempts >= TERMINATE_RETRY_LIMIT)
        {
            LogMessage(L"Process %ls (PID %u) termination attempts exhausted, will stop trying.", exeName, pid);
            *logSent = 1;
        }
        return FALSE;
    }
}

static void CheckProcessHungAndTerminate(PROCESS_HISTORY *hist, DWORD pid, const WCHAR *exeName, HUNG_PROCESS_NODE *hungList)
{
    if (!IsProcessHung(pid, hungList))
    {
        if (hist)
            hist->terminateAttemptsHung = 0;
        return;
    }

    int attempts = hist ? hist->terminateAttemptsHung : 0;
    int logSent = hist ? hist->terminateLogSentHung : 0;

    if (attempts >= TERMINATE_RETRY_LIMIT)
    {
        if (!logSent && hist)
        {
            LogMessage(L"Process %ls (PID %u) is hung but termination attempts exhausted, skipping further attempts", exeName, pid);
            hist->terminateLogSentHung = 1;
        }
        return;
    }

    if (TryTerminateProcess(pid, exeName, &attempts, &logSent))
    {
        RemoveHistory(pid);
    }
    else
    {
        if (hist)
        {
            hist->terminateAttemptsHung = attempts;
            hist->terminateLogSentHung = logSent;
        }
    }
}

static void CheckProcessResourcesAndTerminate(PROCESS_HISTORY *hist, HANDLE hProcess, DWORD pid, const WCHAR *exeName,
                                              const WCHAR *path, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList)
{
    float cpu = 0.0f;
    size_t memMB = 0;
    BOOL memValid = FALSE;

    MeasureProcessResources(hProcess, hist, &cpu, &memMB, &memValid);

    BOOL abnormal = FALSE;
    WCHAR reason[512];
    BOOL hung = IsProcessHung(pid, hungList);
    FormatReason(reason, 512, cpu, cfg->cpuThresholdPercent,
                 memValid, memMB, cfg->memThresholdMb, hung);

    if (reason[0] != L'\0')
    {
        abnormal = TRUE;
    }

    if (abnormal)
    {
        if (hist->terminateAttempts >= TERMINATE_RETRY_LIMIT)
        {
            if (!hist->terminateLogSent)
            {
                LogMessage(L"Process %ls (PID %u) exceeds threshold but termination attempts exhausted, skipping further attempts", exeName, pid);
                hist->terminateLogSent = 1;
            }
            return;
        }

        LogEvent(FALSE, exeName, pid, reason, cpu, memMB, memValid, path);
        if (TryTerminateProcess(pid, exeName, &hist->terminateAttempts, &hist->terminateLogSent))
        {
            RemoveHistory(pid);
        }
    }
    else
    {
        hist->terminateAttempts = 0;
        hist->terminateLogSent = 0;
    }
}

// -------------------- Process Check Functions --------------------
static void CheckNormalProcess(const PROCESSENTRY32W *pe, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList)
{
    WCHAR processPath[INTERNAL_PATH_BUFFER_SIZE] = L"";
    HANDLE hProcess = NULL;

    PROCESS_HISTORY *hist = FindOrCreateHistory(pe->th32ProcessID);
    if (!hist)
    {
        CheckProcessHungAndTerminate(NULL, pe->th32ProcessID, pe->szExeFile, hungList);
        return;
    }

    if (!OpenProcessForQuery(pe->th32ProcessID, &hProcess, processPath, INTERNAL_PATH_BUFFER_SIZE))
    {
        CheckProcessHungAndTerminate(hist, pe->th32ProcessID, pe->szExeFile, hungList);
        return;
    }

    CheckProcessResourcesAndTerminate(hist, hProcess, pe->th32ProcessID, pe->szExeFile,
                                      processPath, cfg, hungList);
    CloseHandle(hProcess);
}

static void CheckSystemProcess(const PROCESSENTRY32W *pe, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList)
{
    WCHAR processPath[INTERNAL_PATH_BUFFER_SIZE] = L"";
    GetProcessPathW(pe->th32ProcessID, processPath, INTERNAL_PATH_BUFFER_SIZE);

    if (IsProcessHung(pe->th32ProcessID, hungList))
    {
        if (ShouldShowBalloonForProcess(pe->szExeFile))
        {
            WCHAR balloonText[512];
            swprintf(balloonText, 512, L"System process %ls (PID %u) has a hung window.\nPath: %ls\n(This could be normal activity; check the path if concerned.)",
                     pe->szExeFile, pe->th32ProcessID, processPath);
            ShowBalloon(L"Suspicious System Process", balloonText, NIIF_WARNING);
        }
        LogEvent(TRUE, pe->szExeFile, pe->th32ProcessID, L"Window not responding",
                 0.0f, 0, FALSE, processPath);
        return;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pe->th32ProcessID);
    if (!hProcess)
    {
        return;
    }

    PROCESS_HISTORY *hist = FindOrCreateHistory(pe->th32ProcessID);
    float instCpu = 0.0f;
    if (hist)
    {
        instCpu = CalcCpuUsage(hProcess, hist);
        if (instCpu < 0)
            instCpu = 0.0f;
    }

    PROCESS_MEMORY_COUNTERS pmc;
    size_t memMB = 0;
    BOOL memValid = FALSE;
    if (GetProcessMemoryInfo(hProcess, &pmc, sizeof(pmc)))
    {
        memMB = pmc.WorkingSetSize / (1024 * 1024);
        memValid = TRUE;
    }

    float avgCpu = CalcAverageCpuUsage(hProcess);
    BOOL cpuValid = (avgCpu >= 0);

    BOOL suspicious = FALSE;
    WCHAR reason[512] = L"";
    if (instCpu > cfg->cpuThresholdPercent)
    {
        swprintf(reason, 512, L"High instantaneous CPU: %.1f%%", instCpu);
        suspicious = TRUE;
    }
    else if (cpuValid && avgCpu > cfg->cpuThresholdPercent)
    {
        swprintf(reason, 512, L"High average CPU: %.1f%%", avgCpu);
        suspicious = TRUE;
    }
    else if (memValid && memMB > cfg->memThresholdMb)
    {
        swprintf(reason, 512, L"High memory: %llu MB", (unsigned long long)memMB);
        suspicious = TRUE;
    }

    if (suspicious)
    {
        if (ShouldShowBalloonForProcess(pe->szExeFile))
        {
            WCHAR balloonText[512];
            swprintf(balloonText, 512, L"System process %ls (PID %u) is using excessive resources.\nCPU: %.1f%% (inst) / %.1f%% (avg)  Memory: %llu MB\nPath: %ls\n(This could be normal activity; check the path if concerned.)",
                     pe->szExeFile, pe->th32ProcessID, instCpu, avgCpu, (unsigned long long)memMB, processPath);
            ShowBalloon(L"Suspicious System Process", balloonText, NIIF_WARNING);
        }
        LogEvent(TRUE, pe->szExeFile, pe->th32ProcessID, reason,
                 (instCpu > 0 ? instCpu : (cpuValid ? avgCpu : 0.0f)), memMB, memValid, processPath);
    }

    CloseHandle(hProcess);
}

BOOL IsBuiltInExcluded(const WCHAR *fileName, const WCHAR *fullPath)
{
    static const WCHAR *systemNames[] = {
        L"csrss.exe", L"services.exe", L"lsass.exe", L"lsm.exe", L"smss.exe", L"wininit.exe",
        L"winlogon.exe", L"system", L"system.exe", L"svchost.exe", L"dwm.exe",
        L"conhost.exe", L"spoolsv.exe", L"taskhost.exe", L"taskhostw.exe",
        L"explorer.exe", L"fontdrvhost.exe", L"SearchIndexer.exe", L"SearchHost.exe",
        L"RuntimeBroker.exe", L"SecurityHealthService.exe", L"SecurityHealthSystray.exe",
        L"SgrmBroker.exe", L"StartMenuExperienceHost.exe", L"TextInputHost.exe",
        L"Widgets.exe", L"WindowsTerminal.exe", L"wlanext.exe",
        L"WmiPrvSE.exe", L"WUDFHost.exe", L"dllhost.exe", L"taskeng.exe",
        L"audiodg.exe", L"LogonUI.exe", L"userinit.exe",
        NULL};

    BOOL nameMatch = FALSE;
    for (int i = 0; systemNames[i] != NULL; i++)
    {
        if (_wcsicmp(fileName, systemNames[i]) == 0)
        {
            nameMatch = TRUE;
            break;
        }
    }
    if (!nameMatch)
        return FALSE;

    if (fullPath == NULL || fullPath[0] == L'\0')
        return TRUE;

    return IsSystemDirectory(fullPath);
}

BOOL IsProcessExcluded(const WCHAR *nameW, const CONFIG *cfg, const WCHAR *path)
{
    for (int i = 0; i < cfg->excludeCount; i++)
    {
        if (_wcsicmp(nameW, cfg->excludeList[i]) == 0)
        {
            return TRUE;
        }
    }
    return FALSE;
}

static void CheckProcess(const PROCESSENTRY32W *pe, const CONFIG *cfg, HUNG_PROCESS_NODE *hungList)
{
    if (pe->th32ProcessID == GetCurrentProcessId())
        return;

    WCHAR exeNameW[MAX_PATH_LEN];
    wcsncpy_s(exeNameW, MAX_PATH_LEN, pe->szExeFile, _TRUNCATE);

    WCHAR pathBuf[INTERNAL_PATH_BUFFER_SIZE] = L"";
    GetProcessPathW(pe->th32ProcessID, pathBuf, INTERNAL_PATH_BUFFER_SIZE);

    if (IsBuiltInExcluded(exeNameW, pathBuf))
    {
        CheckSystemProcess(pe, cfg, hungList);
        return;
    }

    if (IsProcessExcluded(exeNameW, cfg, pathBuf))
    {
        return;
    }

    CheckNormalProcess(pe, cfg, hungList);
}

// -------------------- Configuration File Change Detection --------------------
BOOL CheckConfigFileChanged(void)
{
    WCHAR configPath[MAX_LONG_PATH];
    wcscpy_s(configPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(configPath, MAX_LONG_PATH, L"\\");
    wcscat_s(configPath, MAX_LONG_PATH, CONFIG_FILE);

    DWORD attr = GetFileAttributesW(configPath);
    if (attr == INVALID_FILE_ATTRIBUTES)
    {
        return TRUE;
    }

    HANDLE hFile = CreateFileW(configPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        return TRUE;
    }

    FILETIME ftWrite;
    BOOL success = GetFileTime(hFile, NULL, NULL, &ftWrite);
    CloseHandle(hFile);
    if (!success)
        return FALSE;

    EnterCriticalSection(&g.csConfig);
    BOOL changed = (CompareFileTime(&ftWrite, &g.configLastWrite) != 0);
    LeaveCriticalSection(&g.csConfig);
    return changed;
}

void UpdateConfigLastWrite(void)
{
    EnterCriticalSection(&g.csConfig);
    WCHAR configPath[MAX_LONG_PATH];
    wcscpy_s(configPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(configPath, MAX_LONG_PATH, L"\\");
    wcscat_s(configPath, MAX_LONG_PATH, CONFIG_FILE);

    HANDLE hFile = CreateFileW(configPath, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        GetFileTime(hFile, NULL, NULL, &g.configLastWrite);
        CloseHandle(hFile);
    }
    else
    {
        g.configLastWrite.dwLowDateTime = 0;
        g.configLastWrite.dwHighDateTime = 0;
    }
    LeaveCriticalSection(&g.csConfig);
}

// -------------------- Monitor Thread Helper Functions --------------------
static void HandleConfigReload(ULONGLONG *lastConfigCheck, ULONGLONG *lastConfigFailBalloon)
{
    ULONGLONG now = GetTickCount64();
    if (now - *lastConfigCheck > CONFIG_POLL_INTERVAL_MS || *lastConfigCheck == 0)
    {
        BOOL changed = CheckConfigFileChanged();

        if (changed || g.configLoadFailed)
        {
            WCHAR configPath[MAX_LONG_PATH];
            wcscpy_s(configPath, MAX_LONG_PATH, g.exeDir);
            wcscat_s(configPath, MAX_LONG_PATH, L"\\");
            wcscat_s(configPath, MAX_LONG_PATH, CONFIG_FILE);
            if (GetFileAttributesW(configPath) == INVALID_FILE_ATTRIBUTES)
            {
                CreateDefaultConfig();
            }
            BOOL loadSuccess = LoadConfig();
            if (loadSuccess)
            {
                UpdateConfigLastWrite();
                LogMessage(L"Configuration reloaded from file.");
                g.configLoadFailed = 0;
            }
            else
            {
                LogMessage(L"ERROR: Failed to reload configuration; will retry on next check.");
                g.configLoadFailed = 1;
                if (InterlockedCompareExchange(&g.monitorActive, 0, 0) == 1)
                {
                    ULONGLONG tickNow = GetTickCount64();
                    if (tickNow - *lastConfigFailBalloon >= CONFIG_FAIL_BALLOON_COOLDOWN_MS)
                    {
                        ShowBalloon(L"Process Monitor", L"Failed to reload config, using previous settings", NIIF_WARNING);
                        *lastConfigFailBalloon = tickNow;
                    }
                }
            }
        }
        *lastConfigCheck = now;
    }
}

static void ProcessSnapshot(const CONFIG *localConfig)
{
    RotateLogIfNeeded(localConfig->logMaxSizeBytes);

    HUNG_PROCESS_NODE *hungList = BuildHungProcessList(localConfig->hangTimeoutMs, localConfig->maxHungWindows, g.hStopEvent);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
    {
        static DWORD consecutiveSnapshotFailures = 0;
        consecutiveSnapshotFailures++;
        DWORD err = GetLastError();
        if (consecutiveSnapshotFailures == 1)
        {
            LogError(L"CreateToolhelp32Snapshot failed (err %lu), will retry with backoff.", err);
        }
        else if (consecutiveSnapshotFailures > 3)
        {
            LogError(L"Snapshot has failed %u times consecutively (last err %lu).", consecutiveSnapshotFailures, err);
        }
        ULONGLONG wait = (ULONGLONG)localConfig->monitorIntervalMs;
        if (consecutiveSnapshotFailures > 1)
        {
            int shift = consecutiveSnapshotFailures - 1;
            if (shift > 10)
                shift = 10;
            wait = (ULONGLONG)localConfig->monitorIntervalMs * (1ULL << shift);
        }
        if (wait > MAX_BACKOFF_WAIT_MS)
            wait = MAX_BACKOFF_WAIT_MS;

        FreeHungProcessList(hungList);
        DWORD step = 200;
        for (DWORD elapsed = 0; elapsed < wait; elapsed += step)
        {
            if (WaitForSingleObject(g.hStopEvent, step) == WAIT_OBJECT_0)
            {
                break;
            }
        }
        return;
    }
    {
        static DWORD consecutiveSnapshotFailures = 0;
        if (consecutiveSnapshotFailures > 0)
        {
            LogMessage(L"Snapshot succeeded after %u failures.", consecutiveSnapshotFailures);
            consecutiveSnapshotFailures = 0;
        }
    }

    EnterCriticalSection(&g.csHistory);
    for (PROCESS_HISTORY *h = g.history; h != NULL; h = h->next)
    {
        h->seen = FALSE;
    }
    LeaveCriticalSection(&g.csHistory);

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(PROCESSENTRY32W);
    if (!Process32FirstW(hSnapshot, &pe))
    {
        CloseHandle(hSnapshot);
        FreeHungProcessList(hungList);
        return;
    }

    do
    {
        CheckProcess(&pe, localConfig, hungList);
    } while (Process32NextW(hSnapshot, &pe));

    CloseHandle(hSnapshot);
    FreeHungProcessList(hungList);
    CleanupHistory();
}

// -------------------- Monitor Thread --------------------
DWORD WINAPI MonitorThread(LPVOID lpParam)
{
    ULONGLONG lastConfigCheck = 0;
    ULONGLONG lastConfigFailBalloon = 0;

    while (InterlockedCompareExchange(&g.programRunning, 1, 1) == 1)
    {
        HandleConfigReload(&lastConfigCheck, &lastConfigFailBalloon);

        if (InterlockedCompareExchange(&g.systemResumed, 1, 1) == 1)
        {
            ResetAllHistory();
            InterlockedExchange(&g.systemResumed, 0);
        }

        PeriodicBalloonCleanup();

        CONFIG localConfig;
        EnterCriticalSection(&g.csConfig);
        localConfig = g.config;
        LeaveCriticalSection(&g.csConfig);

        if (InterlockedCompareExchange(&g.monitorActive, 0, 0) == 1)
        {
            ProcessSnapshot(&localConfig);
        }

        WaitForSingleObject(g.hStopEvent, localConfig.monitorIntervalMs);
    }
    return 0;
}

// -------------------- Admin Check --------------------
BOOL IsUserAdmin(void)
{
    BOOL isAdmin = FALSE;
    PSID adminGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                 DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup))
    {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }
    return isAdmin;
}

// -------------------- Executable Directory --------------------
void GetExeDirectory(void)
{
    WCHAR exePath[MAX_LONG_PATH];
    GetModuleFileNameW(NULL, exePath, MAX_LONG_PATH);
    WCHAR *p = wcsrchr(exePath, L'\\');
    if (p)
    {
        *p = L'\0';
        wcscpy_s(g.exeDir, MAX_LONG_PATH, exePath);
    }
    else
    {
        GetCurrentDirectoryW(MAX_LONG_PATH, g.exeDir);
    }
}

// -------------------- Configuration Handling --------------------
static WCHAR *TrimWhitespace(WCHAR *str)
{
    while (*str == L' ' || *str == L'\t')
        str++;
    if (*str == L'\0')
        return str;

    WCHAR *end = str + wcslen(str) - 1;
    while (end > str && (*end == L' ' || *end == L'\t'))
        end--;
    end[1] = L'\0';
    return str;
}

static void SplitExcludeString(const WCHAR *input, WCHAR excludeList[MAX_EXCLUDE_COUNT][MAX_PATH_LEN], int *count, BOOL *hadWarning)
{
    *count = 0;
    *hadWarning = FALSE;
    if (!input || input[0] == L'\0')
        return;

    const WCHAR *p = input;
    const WCHAR *start;
    WCHAR token[MAX_PATH_LEN];
    int len;

    while (*p && *count < MAX_EXCLUDE_COUNT)
    {
        while (*p == L',' || *p == L';')
            p++;
        while (*p == L' ' || *p == L'\t')
            p++;
        if (*p == L'\0')
            break;
        start = p;
        while (*p && *p != L',' && *p != L';')
            p++;
        const WCHAR *end = p - 1;
        while (end >= start && (*end == L' ' || *end == L'\t'))
            end--;
        len = (int)(end - start + 1);
        if (len >= MAX_PATH_LEN)
            len = MAX_PATH_LEN - 1;
        wcsncpy_s(token, MAX_PATH_LEN, start, len);
        token[len] = L'\0';

        if (wcschr(token, L'*') || wcschr(token, L'?'))
        {
            LogMessage(L"Warning: Exclude entry '%ls' contains wildcard (* or ?) and will be ignored. Wildcards are not supported.", token);
            *hadWarning = TRUE;
        }
        else if (wcschr(token, L'\\') || wcschr(token, L'/'))
        {
            LogMessage(L"Warning: Exclude entry '%ls' contains a path separator and will be ignored. Use only file names.", token);
            *hadWarning = TRUE;
        }
        else if (wcslen(token) >= MAX_PATH_LEN - 1)
        {
            LogMessage(L"Warning: Exclude entry '%ls' is too long and has been truncated to %d characters.", token, MAX_PATH_LEN - 1);
            *hadWarning = TRUE;
            wcsncpy_s(excludeList[*count], MAX_PATH_LEN, token, _TRUNCATE);
            (*count)++;
        }
        else if (wcslen(token) > 0)
        {
            wcsncpy_s(excludeList[*count], MAX_PATH_LEN, token, _TRUNCATE);
            (*count)++;
        }
    }
    if (*count >= MAX_EXCLUDE_COUNT && *p)
    {
        LogMessage(L"Warning: Exclusion list truncated to %d entries (max)", MAX_EXCLUDE_COUNT);
        *hadWarning = TRUE;
    }
}

BOOL LoadConfig(void)
{
    WCHAR configPath[MAX_LONG_PATH];
    wcscpy_s(configPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(configPath, MAX_LONG_PATH, L"\\");
    wcscat_s(configPath, MAX_LONG_PATH, CONFIG_FILE);

    if (GetFileAttributesW(configPath) == INVALID_FILE_ATTRIBUTES)
    {
        return FALSE;
    }

    CONFIG newConfig;
    newConfig.monitorIntervalMs = GetPrivateProfileIntW(L"Settings", L"MonitorIntervalMs", DEFAULT_MONITOR_INTERVAL_MS, configPath);
    newConfig.cpuThresholdPercent = GetPrivateProfileIntW(L"Settings", L"CpuThresholdPercent", DEFAULT_CPU_THRESHOLD_PERCENT, configPath);
    newConfig.memThresholdMb = GetPrivateProfileIntW(L"Settings", L"MemThresholdMb", DEFAULT_MEM_THRESHOLD_MB, configPath);
    newConfig.hangTimeoutMs = GetPrivateProfileIntW(L"Settings", L"HangTimeoutMs", DEFAULT_HANG_TIMEOUT_MS, configPath);
    newConfig.logMaxSizeBytes = GetPrivateProfileIntW(L"Settings", L"LogMaxSizeBytes", DEFAULT_LOG_MAX_SIZE_BYTES, configPath);
    newConfig.maxHungWindows = GetPrivateProfileIntW(L"Settings", L"MaxHungWindows", DEFAULT_MAX_HUNG_WINDOWS, configPath);
    newConfig.notifyOnTermination = GetPrivateProfileIntW(L"Settings", L"NotifyOnTermination", DEFAULT_NOTIFY_ON_TERMINATION, configPath) != 0;
    newConfig.monitoringDefault = GetPrivateProfileIntW(L"Settings", L"StartMonitoringOnLaunch", 1, configPath) != 0;

    BOOL clamped = FALSE;
    ULONGLONG now = GetTickCount64();

#define CLAMP(field, min, max, name)                                                                               \
    {                                                                                                              \
        DWORD orig = newConfig.field;                                                                              \
        if (newConfig.field < min)                                                                                 \
        {                                                                                                          \
            newConfig.field = min;                                                                                 \
            clamped = TRUE;                                                                                        \
        }                                                                                                          \
        if (newConfig.field > max)                                                                                 \
        {                                                                                                          \
            newConfig.field = max;                                                                                 \
            clamped = TRUE;                                                                                        \
        }                                                                                                          \
        if (newConfig.field != orig)                                                                               \
        {                                                                                                          \
            LogMessage(L"Config " name L" adjusted from %u to %u (range %u-%u)", orig, newConfig.field, min, max); \
        }                                                                                                          \
    }
    CLAMP(monitorIntervalMs, MIN_MONITOR_INTERVAL_MS, MAX_MONITOR_INTERVAL_MS, L"MonitorIntervalMs");
    CLAMP(cpuThresholdPercent, MIN_CPU_THRESHOLD, MAX_CPU_THRESHOLD, L"CpuThresholdPercent");
    CLAMP(memThresholdMb, MIN_MEM_THRESHOLD_MB, MAX_MEM_THRESHOLD_MB, L"MemThresholdMb");
    CLAMP(hangTimeoutMs, MIN_HANG_TIMEOUT_MS, MAX_HANG_TIMEOUT_MS, L"HangTimeoutMs");
    CLAMP(logMaxSizeBytes, MIN_LOG_SIZE_BYTES, MAX_LOG_SIZE_BYTES, L"LogMaxSizeBytes");
    CLAMP(maxHungWindows, MIN_MAX_HUNG_WINDOWS, MAX_MAX_HUNG_WINDOWS, L"MaxHungWindows");
#undef CLAMP

    if (clamped && (now - g.lastClampWarningTick >= WARNING_COOLDOWN_MS))
    {
        ShowBalloon(L"Configuration Notice", L"Some settings were outside allowed range and have been adjusted. Check log for details.", NIIF_INFO);
        g.lastClampWarningTick = now;
    }

    int newExcludeCount = 0;
    WCHAR newExcludeList[MAX_EXCLUDE_COUNT][MAX_PATH_LEN] = {0};
    BOOL excludeWarning = FALSE;

    DWORD excludeSize = GetPrivateProfileStringW(L"Settings", L"ExcludeProcesses", L"", NULL, 0, configPath);
    if (excludeSize > 0)
    {
        WCHAR *excludeBuffer = (WCHAR *)malloc(excludeSize * sizeof(WCHAR));
        if (excludeBuffer)
        {
            DWORD copied = GetPrivateProfileStringW(L"Settings", L"ExcludeProcesses", L"",
                                                    excludeBuffer, excludeSize, configPath);
            if (copied > 0)
            {
                SplitExcludeString(excludeBuffer, newExcludeList, &newExcludeCount, &excludeWarning);
            }
            free(excludeBuffer);
        }
        else
        {
            LogError(L"Failed to allocate memory for exclude list; exclude list will be empty.");
        }
    }

    if (excludeWarning && (now - g.lastExcludeWarningTick >= WARNING_COOLDOWN_MS))
    {
        ShowBalloon(L"Exclude List Notice", L"Some entries in ExcludeProcesses were invalid (path separators, wildcards, or too long). They have been ignored. Check log for details.", NIIF_WARNING);
        g.lastExcludeWarningTick = now;
    }

    HANDLE hFile = CreateFileW(configPath, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile != INVALID_HANDLE_VALUE)
    {
        BYTE buffer[256];
        DWORD read;
        if (ReadFile(hFile, buffer, sizeof(buffer) - 1, &read, NULL) && read > 0)
        {
            buffer[read] = 0;
            BOOL hasBOM = (read >= 2 && buffer[0] == 0xFF && buffer[1] == 0xFE) ||
                          (read >= 3 && buffer[0] == 0xEF && buffer[1] == 0xBB && buffer[2] == 0xBF);
            if ((hasBOM || (read > 0 && buffer[0] > 127)) &&
                (now - g.lastEncodingWarningTick >= ENCODING_WARNING_COOLDOWN_MS))
            {
                if (hasBOM)
                {
                    LogMessage(L"NOTE: Configuration file appears to contain a Byte Order Mark (BOM). For proper reading, please open config.ini in Notepad, click File -> Save As, choose 'ANSI' in the Encoding dropdown, and save.");
                    ShowBalloon(L"Config Encoding", L"config.ini has BOM. Save as ANSI using Notepad (File -> Save As -> Encoding: ANSI).", NIIF_WARNING);
                }
                else
                {
                    LogMessage(L"NOTE: Configuration file contains non-ASCII characters. It may be saved in UTF-8. For proper reading, please open config.ini in Notepad, click File -> Save As, choose 'ANSI' in the Encoding dropdown, and save.");
                    ShowBalloon(L"Config Encoding", L"config.ini may be UTF-8. Save as ANSI using Notepad (File -> Save As -> Encoding: ANSI).", NIIF_WARNING);
                }
                g.lastEncodingWarningTick = now;
            }
        }
        CloseHandle(hFile);
    }

    EnterCriticalSection(&g.csConfig);
    g.config = newConfig;
    g.config.excludeCount = newExcludeCount;
    memcpy(g.config.excludeList, newExcludeList, sizeof(newExcludeList));
    LeaveCriticalSection(&g.csConfig);

    return TRUE;
}

void CreateDefaultConfig(void)
{
    WCHAR configPath[MAX_LONG_PATH];
    wcscpy_s(configPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(configPath, MAX_LONG_PATH, L"\\");
    wcscat_s(configPath, MAX_LONG_PATH, CONFIG_FILE);

    FILE *f = _wfopen(configPath, L"w");
    if (f)
    {
        fprintf(f, "[Settings]\n");
        fprintf(f, "MonitorIntervalMs=5000\n");
        fprintf(f, "CpuThresholdPercent=80\n");
        fprintf(f, "MemThresholdMb=500\n");
        fprintf(f, "HangTimeoutMs=5000\n");
        fprintf(f, "LogMaxSizeBytes=1048576\n");
        fprintf(f, "MaxHungWindows=500\n");
        fprintf(f, "NotifyOnTermination=0\n");
        fprintf(f, "StartMonitoringOnLaunch=1\n");
        fprintf(f, "ExcludeProcesses=\n\n");
        fprintf(f, "; Process Monitor Configuration File\n");
        fprintf(f, "; All times are in milliseconds.\n");
        fprintf(f, "; Edit values as needed. The program will automatically reload changes.\n");
        fprintf(f, "; StartMonitoringOnLaunch: 1 to start monitoring automatically, 0 to start stopped.\n");
        fprintf(f, "; NotifyOnTermination: 1 to show a balloon when a normal process is terminated, 0 to only log.\n");
        fprintf(f, "; ExcludeProcesses: comma or semicolon separated list (e.g., notepad.exe,calc.exe)\n");
        fprintf(f, "; Note: CPU threshold is total process CPU time (may exceed 100%% on multi-core).\n");
        fprintf(f, "; MaxHungWindows: limit number of windows to check for hanging (10-5000).\n");
        fprintf(f, "; IMPORTANT: Save this file in ANSI encoding (system default code page).\n");
        fprintf(f, "; If you use UTF-8 without BOM, non-ASCII characters may not be read correctly.\n");
        fclose(f);
    }
    else
    {
        MessageBox(NULL, L"Failed to create default config.ini. Please check write permissions in the program folder.", L"Error", MB_OK | MB_ICONERROR);
        OutputDebugStringA("ERROR: Failed to create default config file\n");
    }
}

// -------------------- Show Balloon --------------------
static void ShowBalloon(const WCHAR *title, const WCHAR *text, DWORD infoFlags)
{
    NOTIFYICONDATA nid = {0};
    nid.cbSize = sizeof(NOTIFYICONDATA);
    nid.hWnd = g.hWnd;
    nid.uID = 1;
    nid.uFlags = NIF_INFO;
    nid.dwInfoFlags = infoFlags;
    wcsncpy_s(nid.szInfoTitle, 64, title, _TRUNCATE);
    wcsncpy_s(nid.szInfo, 256, text, _TRUNCATE);
    Shell_NotifyIcon(NIM_MODIFY, &g.nid);
}

// -------------------- Show Status Dialog (simple MessageBox) --------------------
static void ShowStatusDialog(HWND hwnd)
{
    WCHAR status[256];
    swprintf(status, 256, L"Process Monitor v%s\n\nMonitoring is %s.",
             VERSION_STRING,
             InterlockedCompareExchange(&g.monitorActive, 0, 0) ? L"ON" : L"OFF");
    MessageBoxW(hwnd, status, L"Process Monitor", MB_OK | MB_ICONINFORMATION);
}

// -------------------- OS Version Check --------------------
BOOL IsWindowsVersionSupported(void)
{
    return IsWindowsVistaOrGreater();
}

// -------------------- Temporary Log File Cleanup --------------------
static void CleanupTemporaryLogFile(void)
{
    WCHAR tempPath[MAX_LONG_PATH];
    wcscpy_s(tempPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(tempPath, MAX_LONG_PATH, L"\\");
    wcscat_s(tempPath, MAX_LONG_PATH, LOG_TEMP_FILE);
    _wremove(tempPath);
}

static void DeleteTemporaryLogFile(void)
{
    WCHAR tempPath[MAX_LONG_PATH];
    wcscpy_s(tempPath, MAX_LONG_PATH, g.exeDir);
    wcscat_s(tempPath, MAX_LONG_PATH, L"\\");
    wcscat_s(tempPath, MAX_LONG_PATH, LOG_TEMP_FILE);
    _wremove(tempPath);
}

// -------------------- Cleanup --------------------
void Cleanup(void)
{
    InterlockedExchange(&g.programRunning, 0);
    if (g.hMonitorThread)
    {
        SetEvent(g.hStopEvent);
        for (int i = 0; i < 10; i++)
        {
            if (WaitForSingleObject(g.hMonitorThread, 500) == WAIT_OBJECT_0)
                break;
        }
        CloseHandle(g.hMonitorThread);
        g.hMonitorThread = NULL;
    }

    if (g.hWnd)
    {
        DestroyWindow(g.hWnd);
        g.hWnd = NULL;
    }

    CloseLogFile();

    DeleteTemporaryLogFile();

    CleanupBalloonCooldown();

    // No custom icon to destroy

    EnterCriticalSection(&g.csHistory);
    PROCESS_HISTORY *curr = g.history;
    while (curr)
    {
        PROCESS_HISTORY *tmp = curr;
        curr = curr->next;
        free(tmp);
    }
    g.history = NULL;
    LeaveCriticalSection(&g.csHistory);

    DeleteCriticalSection(&g.csHistory);
    DeleteCriticalSection(&g.csLog);
    DeleteCriticalSection(&g.csConfig);
    DeleteCriticalSection(&g.csBalloon);

    if (g.hMutex)
        CloseHandle(g.hMutex);
}